"""Journaled explicit repairs, revalidation, verification and selected restore planning."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4

import discord

from serversentry_repair_model import (
    build_plan, check_saved_plan, fingerprint, guild_state, now, snowflake, validate_policy,
)
from serversentry_snapshots import atomic_write, fsync_directory, prepare_snapshot


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
    fsync_directory(path.parent)


def write_json(path: Path, data: dict) -> None:
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def save_private_json(base: Path, prefix: str, data: dict) -> Path:
    """Compatible helper for the optional role-mute tool, now with atomic private writes."""
    private_directory(base)
    path = base / f"{prefix}_{uuid4().hex}.json"
    write_json(path, data)
    return path


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read JSON file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def audit_evidence(guild, directory: Path) -> dict:
    # Lazy imports: comparison/report commands themselves remain standard-library only.
    from discord_audit import audit_guild, markdown_report
    from serversentry_report import render_html
    private_directory(directory)
    snapshot = prepare_snapshot(audit_guild(guild))
    snapshot["audit"]["channel_inventory"] = "rest_guild_channels"
    snapshot["audit"]["limitations"] = [
        limitation.replace("only cached guild channels are inspected", "only REST-listed guild channels are inspected")
        for limitation in snapshot["audit"]["limitations"]
    ]
    atomic_write(directory / "report.md", markdown_report(snapshot))
    atomic_write(directory / "report.html", render_html(snapshot))
    write_json(directory / "snapshot.json", snapshot)
    return snapshot


async def write_step(guild, item: dict, run_id: str) -> None:
    action = item["source"]
    op = item["operation"]
    reason = f"ServerSentry {run_id[:8]} step {item['index']}: " + action.get("reason", op)[:350]
    if op == "role_permissions":
        role = guild.get_role(int(action["role_id"]))
        effect = next(e for e in item["effects"] if e["kind"] == "role" and e["id"] == str(role.id))
        await role.edit(permissions=discord.Permissions(int(effect["after"]["permissions"])), reason=reason)
    elif op == "channel_role_permissions":
        channel = guild.get_channel(int(action["channel_id"]))
        role = guild.get_role(int(action["role_id"]))
        effect = next(e for e in item["effects"] if e["kind"] == "channel" and e["id"] == str(channel.id))
        overwrite = effect["after"]["overwrites"].get("role:" + str(role.id))
        if overwrite is None:
            await channel.set_permissions(role, overwrite=None, reason=reason)
        else:
            # PermissionOverwrite.from_pair discards unknown future bits. Submit
            # the preflighted raw pair through the same HTTP method instead.
            await guild.raw._state.http.edit_channel_permissions(
                channel.id, role.id, overwrite["allow"], overwrite["deny"], 0, reason=reason
            )
    elif op == "remove_member_overwrite":
        channel = guild.get_channel(int(action["channel_id"]))
        member = guild.get_member(int(action["user_id"]))
        if member is None:
            raise ValueError("Target member is no longer available")
        await channel.set_permissions(member, overwrite=None, reason=reason)
    elif op == "sync_channel":
        await guild.get_channel(int(action["channel_id"])).edit(sync_permissions=True, reason=reason)
    elif op == "move_role_below":
        positions = {guild.get_role(int(e["id"])): e["after"]["position"]
                     for e in item["effects"] if e["kind"] == "role"}
        await guild.raw.edit_role_positions(positions=positions, reason=reason)
    elif op == "delete_channel":
        await guild.get_channel(int(action["channel_id"])).delete(reason=reason)
    else:
        raise ValueError(f"Unsupported write operation: {op}")


def _verification(steps: list[dict], observed: dict) -> dict:
    """Compare the last attempted expectation per resource; step status retains uncertainty."""
    expected = {}
    for step in steps:
        if step["status"] in ("verified", "verification_mismatch", "unverified", "failed_outcome_unknown", "in_progress", "journal_failed"):
            for effect in step["plan"]["effects"]:
                expected[(effect["kind"], effect["id"])] = effect["after"]
    resources = []
    for (kind, identifier), desired in sorted(expected.items()):
        actual = observed[kind + "s"].get(identifier)
        if kind == "channel" and desired is not None and (actual is None or actual.get("obfuscated")):
            status = "unverified"
        elif actual == desired:
            status = "matches"
        else:
            status = "mismatch"
        # Missing deleted channels cannot establish successful deletion by visibility alone.
        if kind == "channel" and desired is None:
            status = "absent_from_inventory" if actual is None else "mismatch"
        resources.append({"kind": kind, "id": identifier, "status": status,
                          "expected": desired, "observed": actual})
    return {"status": "matches" if all(r["status"] in ("matches", "absent_from_inventory") for r in resources) else "unverified",
            "resources": resources, "note": "Permission state was read again through REST; missing channels alone do not prove deletion."}


async def execute_plan(plan: dict, refresh, output: Path, *, destructive_sync=False, grants=False) -> tuple[dict, Path]:
    """Call only after explicit confirmation. refresh must perform new REST reads."""
    initial = await refresh()
    check_saved_plan(plan, initial, destructive_sync=destructive_sync, grants=grants)
    private_directory(output)
    run_id = uuid4().hex
    run = output / f"run_{run_id}"
    run.mkdir(mode=0o700)
    fsync_directory(output)
    baseline = guild_state(initial)
    write_json(run / "backup.json", {"version": 2, "captured_at": now(), "state": baseline})
    before_audit = audit_evidence(initial, run / "before")
    journal = {"version": 2, "run_id": run_id, "guild_id": str(initial.id), "started_at": now(),
               "status": "running", "reviewed_plan": deepcopy(plan),
               "steps": [{"plan": deepcopy(item), "status": "pending"} for item in plan["actions"]],
               "verification": {"status": "pending"}}
    journal_path = run / "journal.json"
    write_json(journal_path, journal)  # Must succeed before any Discord write.
    try:
        for step in journal["steps"]:
            item = step["plan"]
            try:
                current = await refresh()
                if fingerprint(guild_state(current)) != item["guard_before"]:
                    raise ValueError("Server changed after planning; stopped before the next write")
                # The fingerprint includes bot membership, capabilities and the projected sequence.
                if not item["changed"]:
                    step.update(status="unchanged", finished_at=now())
                    write_json(journal_path, journal)
                    continue
                step.update(status="in_progress", started_at=now())
                write_json(journal_path, journal)
                try:
                    await write_step(current, item, run_id)
                except Exception as exc:
                    step.update(status="failed_outcome_unknown", error=f"{type(exc).__name__}: {exc}", finished_at=now())
                    journal["status"] = "stopped"
                    write_json(journal_path, journal)
                    break
                try:
                    observed = await refresh()
                    matches = fingerprint(guild_state(observed)) == item["guard_after"]
                    step.update(status="verified" if matches else "verification_mismatch", finished_at=now())
                    if not matches:
                        step["error"] = "Observed state differs from the reviewed projection; remaining writes stopped"
                except Exception as exc:
                    step.update(status="unverified", error=f"{type(exc).__name__}: {exc}", finished_at=now())
                write_json(journal_path, journal)
                if step["status"] != "verified":
                    journal["status"] = "stopped"
                    break
            except Exception as exc:
                status = "blocked" if step["status"] == "pending" else "journal_failed"
                step.update(status=status, error=f"{type(exc).__name__}: {exc}", finished_at=now())
                journal["status"] = "stopped"
                write_json(journal_path, journal)
                break
        else:
            journal["status"] = "completed"
    except BaseException:
        # A crash/cancellation may leave an in-progress request; never describe it as rolled back.
        journal["status"] = "interrupted"
        raise
    finally:
        for step in journal["steps"]:
            if step["status"] == "pending": step["status"] = "not_run"
        try:
            observed = await refresh()
            state = guild_state(observed)
            journal["verification"] = _verification(journal["steps"], state)
            after_audit = audit_evidence(observed, run / "after")
            from serversentry_compare import compare_snapshots
            from serversentry_report import render_html
            comparison = compare_snapshots(before_audit, after_audit)
            write_json(run / "comparison.json", comparison)
            atomic_write(run / "comparison.html", render_html(after_audit, comparison, before_audit))
            if journal["verification"]["status"] != "matches" and journal["status"] == "completed":
                journal["status"] = "verification_failed"
        except Exception as exc:
            journal["verification"] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            if journal["status"] == "completed": journal["status"] = "verification_failed"
        journal["finished_at"] = now()
        write_json(journal_path, journal)
    return journal, run


def _restore_policy(journal: dict, selected: list[int]) -> tuple[dict, list[str]]:
    """Generate guarded inverses only for selected, individually verified supported steps."""
    if not isinstance(journal, dict) or journal.get("version") != 2 or not isinstance(journal.get("steps"), list):
        raise ValueError("Unsupported repair journal")
    guild_id = str(journal.get("guild_id", ""))
    snowflake(guild_id, "journal.guild_id")
    if not selected or len(selected) != len(set(selected)) or any(type(x) is not int or x < 1 or x > len(journal["steps"]) for x in selected):
        raise ValueError("Choose valid, unique journal step numbers with --steps")
    reviewed = journal.get("reviewed_plan", {})
    protected = reviewed.get("policy", {}).get("protected_role_ids", [])
    policy = {"version": 1, "guild_id": guild_id, "protected_role_ids": deepcopy(protected), "actions": []}
    notes = []
    for number in sorted(selected, reverse=True):
        step = journal["steps"][number - 1]
        if not isinstance(step, dict) or step.get("status") != "verified":
            raise ValueError(f"Step {number} is not individually verified; review its actual outcome manually")
        item = step.get("plan", {})
        operation = item.get("operation")
        source = item.get("source", {})
        if operation not in ("role_permissions", "channel_role_permissions"):
            raise ValueError(f"Step {number} ({operation}) cannot be restored automatically; no writes performed")
        effects = item.get("effects", [])
        rid = str(source.get("role_id", ""))
        reason = f"Restore selected journal step {number}"
        if operation == "role_permissions":
            effect = next((x for x in effects if x.get("kind") == "role" and x.get("id") == rid), None)
            if not effect or not isinstance(effect.get("before"), dict) or not isinstance(effect.get("after"), dict):
                raise ValueError(f"Step {number}: missing role recovery evidence")
            before = discord.Permissions(int(effect["before"]["permissions"]))
            after = discord.Permissions(int(effect["after"]["permissions"]))
            if before.administrator and not after.administrator:
                raise ValueError("Administrator cannot be granted by restoration; handle this manually")
            grant = [flag for flag, value in before if value and not getattr(after, flag)]
            revoke = [flag for flag, value in after if value and not getattr(before, flag)]
            action = {"type": operation, "role_id": rid, "grant": grant, "revoke": revoke,
                      "allow_admin_role_edit": True, "allow_privilege_grant": True,
                      "expected_current": {"value": deepcopy(effect["after"])}, "reason": reason}
        else:
            cid = str(source.get("channel_id", ""))
            effect = next((x for x in effects if x.get("kind") == "channel" and x.get("id") == cid), None)
            if not effect or not isinstance(effect.get("before"), dict) or not isinstance(effect.get("after"), dict):
                raise ValueError(f"Step {number}: missing overwrite recovery evidence")
            old = effect["before"]["overwrites"].get("role:" + rid)
            current = effect["after"]["overwrites"].get("role:" + rid)
            left = discord.PermissionOverwrite.from_pair(discord.Permissions(int((old or {}).get("allow", 0))), discord.Permissions(int((old or {}).get("deny", 0))))
            right = discord.PermissionOverwrite.from_pair(discord.Permissions(int((current or {}).get("allow", 0))), discord.Permissions(int((current or {}).get("deny", 0))))
            edits = {flag: value for flag, value in left if value != getattr(right, flag)}
            if not edits:
                raise ValueError(f"Step {number}: no recoverable named permission changes")
            action = {"type": operation, "role_id": rid, "channel_id": cid, "set": edits,
                      "remove_if_empty": old is None, "allow_privilege_grant": True,
                      "allow_managed_role_override": source.get("allow_managed_role_override", False),
                      "expected_current": {"value": deepcopy(current)}, "reason": reason}
        policy["actions"].append(action)
        notes.append(f"Step {number}: inverse requires current state to match its verified result")
    return validate_policy(policy), notes


def restore_policy(journal: dict, selected: list[int]) -> tuple[dict, list[str]]:
    try:
        return _restore_policy(journal, selected)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ValueError("Malformed recovery evidence in the journal; no recovery plan created") from exc
