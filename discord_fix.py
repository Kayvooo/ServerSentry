#!/usr/bin/env python3
"""ServerSentry: explicit, one-shot, policy-driven Discord permission fixes.

There are NO server IDs, member IDs, default targets, or background watchers.
Nothing is written to Discord without --apply, exact confirmation and a backup.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

import discord
from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "fixer_output"
ACTION_TYPES = {"role_permissions", "channel_role_permissions", "mute_role_visibility",
                "cleanup_member_overrides", "sync_channel", "move_role_below", "delete_channel"}
PRIVILEGED = {"administrator", "manage_guild", "manage_roles", "manage_channels",
              "manage_webhooks", "ban_members", "kick_members", "moderate_members"}


def snowflake(value: Any, label: str) -> int:
    raw = str(value)
    if not raw.isdecimal() or not (15 <= len(raw) <= 21):
        raise ValueError(f"{label} must be a Discord numeric snowflake ID (not a placeholder): {raw!r}")
    return int(raw)


def validate_policy(data: dict) -> dict:
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("Policy must be a JSON object with version: 1")
    if not isinstance(data.get("actions"), list):
        raise ValueError("Policy must have an actions array")
    protected = data.get("protected_role_ids", [])
    if not isinstance(protected, list):
        raise ValueError("protected_role_ids must be an array")
    for rid in protected:
        snowflake(rid, "protected_role_id")
    for idx, a in enumerate(data["actions"]):
        if not isinstance(a, dict) or a.get("type") not in ACTION_TYPES:
            raise ValueError(f"Unknown action at index {idx}")
        kind = a["type"]
        needed = {"role_permissions": ("role_id",), "channel_role_permissions": ("channel_id", "role_id"),
                  "mute_role_visibility": ("role_id",), "cleanup_member_overrides": ("user_id",),
                  "sync_channel": ("channel_id",), "move_role_below": ("role_id", "anchor_role_id"),
                  "delete_channel": ("channel_id", "confirm_name")}[kind]
        for name in needed:
            if name not in a:
                raise ValueError(f"Action {idx} ({kind}) missing {name}")
            if name.endswith("_id"):
                snowflake(a[name], f"actions[{idx}].{name}")
        if kind == "role_permissions":
            grants, revokes = a.get("grant", []), a.get("revoke", [])
            if not isinstance(grants, list) or not isinstance(revokes, list) or not (grants or revokes):
                raise ValueError(f"Action {idx}: grant/revoke must be arrays with at least one flag")
            if set(grants) & set(revokes):
                raise ValueError(f"Action {idx}: conflicting grant and revoke")
            for flag in grants + revokes:
                if flag not in discord.Permissions.VALID_FLAGS:
                    raise ValueError(f"Invalid guild permission: {flag}")
            if "administrator" in grants:
                raise ValueError("Granting Administrator is deliberately unsupported")
        if kind == "channel_role_permissions":
            edits = a.get("set")
            if not isinstance(edits, dict) or not edits:
                raise ValueError(f"Action {idx}: set must be a nonempty object")
            for flag, value in edits.items():
                if flag not in discord.PermissionOverwrite.VALID_NAMES or value not in (True, False, None):
                    raise ValueError(f"Invalid channel overwrite {flag}={value!r}")
        if kind == "delete_channel" and (not isinstance(a["confirm_name"], str) or not a["confirm_name"]):
            raise ValueError("delete_channel needs exact confirm_name")
    return data


def load_policy(path: Path) -> dict:
    return validate_policy(json.loads(path.read_text(encoding="utf-8")))


def role_overwrite_snapshot(channel: discord.abc.GuildChannel) -> dict[str, Any]:
    """Records raw bits; member-specific IDs stay only in locally ignored backups."""
    return {str(obj.id): {"kind": "role" if isinstance(obj, discord.Role) else "member",
                          "allow": str(ow.pair()[0].value), "deny": str(ow.pair()[1].value)}
            for obj, ow in channel.overwrites.items()}


def guild_backup(guild: discord.Guild) -> dict[str, Any]:
    return {"guild_id": str(guild.id), "guild_name": guild.name,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "roles": [{"id": str(r.id), "name": r.name, "position": r.position,
                       "permissions": str(r.permissions.value)} for r in guild.roles],
            "channels": [{"id": str(c.id), "name": c.name, "type": str(c.type),
                          "category_id": str(c.category_id) if c.category_id else None,
                          "overwrites": role_overwrite_snapshot(c)} for c in guild.channels]}


def save_private_json(base: Path, prefix: str, data: dict) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        base.chmod(0o700)
    p = base / f"{prefix}_{datetime.now(timezone.utc):%Y%m%d_%H%M%S_%f}.json"
    with p.open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    if os.name != "nt":
        p.chmod(0o600)
    return p


def visible_channel_scope(guild: discord.Guild) -> list[discord.abc.GuildChannel]:
    """Only categories and *unsynced* descendants. Synced children inherit category."""
    cats = sorted((c for c in guild.channels if isinstance(c, discord.CategoryChannel)), key=lambda c: c.id)
    others = sorted((c for c in guild.channels if not isinstance(c, discord.CategoryChannel)
                     and not (c.category and c.permissions_synced)), key=lambda c: c.id)
    return cats + others


def member_override_targets(guild: discord.Guild, uid: int):
    return [(ch, target, ow) for ch in guild.channels for target, ow in ch.overwrites.items()
            if target.id == uid and not isinstance(target, discord.Role)]


def target_role(guild, rid, protected):
    rid = snowflake(rid, "role_id")
    if rid in protected:
        raise ValueError(f"Role {rid} is protected by policy")
    r = guild.get_role(rid)
    if r is None or r.is_default():
        raise ValueError(f"Role {rid} not found or @everyone is protected")
    return r


def target_channel(guild, cid):
    c = guild.get_channel(snowflake(cid, "channel_id"))
    if c is None:
        raise ValueError(f"Channel {cid} not found or not visible to bot")
    return c


def make_plan(guild: discord.Guild, policy: dict, *, destructive_sync: bool, grants: bool) -> list[dict]:
    """Validate all actions before any write. Never infer private-channel intent from names."""
    protected = {snowflake(x, "protected_role_id") for x in policy.get("protected_role_ids", [])}
    planned: list[dict] = []
    for i, a in enumerate(policy["actions"], 1):
        kind = a["type"]
        details: dict[str, Any] = {"index": i, "type": kind, "reason": a.get("reason", "User-configured action"),
                                    "source": a}
        if kind == "role_permissions":
            role = target_role(guild, a["role_id"], protected)
            if role.managed:
                raise ValueError(f"Managed/integration role cannot be edited: {role.name}")
            if role.permissions.administrator and not a.get("allow_admin_role_edit", False):
                raise ValueError(f"Admin role {role.name}: set allow_admin_role_edit in explicit action to review")
            flags = role.permissions
            if any(x in PRIVILEGED for x in a.get("grant", [])) and not (grants and a.get("allow_privilege_grant")):
                raise ValueError("Privileged grants need both action allow_privilege_grant and --allow-privilege-grants")
            new = discord.Permissions(flags.value)
            for p in a.get("grant", []): setattr(new, p, True)
            for p in a.get("revoke", []): setattr(new, p, False)
            details.update(label=f"role {role.name}: permissions", before=flags.value, after=new.value,
                           changed=new.value != flags.value)
        elif kind == "channel_role_permissions":
            ch = target_channel(guild, a["channel_id"])
            role = target_role(guild, a["role_id"], protected)
            if role.managed and not a.get("allow_managed_role_override", False):
                raise ValueError(f"Managed role override {role.name} needs explicit allow_managed_role_override")
            old = ch.overwrites_for(role)
            new = discord.PermissionOverwrite.from_pair(*old.pair())
            for key, value in a["set"].items(): setattr(new, key, value)
            details.update(label=f"{ch.name}: override for {role.name}", before=list(x.value for x in old.pair()),
                           after=list(x.value for x in new.pair()), changed=old.pair()!=new.pair())
        elif kind == "mute_role_visibility":
            role = target_role(guild, a["role_id"], protected)
            if role.permissions.administrator:
                raise ValueError("Admin role cannot be used as muted visibility role")
            scoped = visible_channel_scope(guild)
            targets = [ch for ch in scoped if ch.overwrites_for(role).view_channel is not False]
            details.update(label=f"Mute role {role.name}: deny View Channel in {len(targets)} category/channel(s)",
                           affected_channels=[{"id":str(ch.id), "name":ch.name} for ch in targets],
                           changed=bool(targets))
        elif kind == "cleanup_member_overrides":
            uid = snowflake(a["user_id"], "user_id")
            targets = member_override_targets(guild, uid)
            details.update(label=f"Remove {len(targets)} personal channel overrides for member {uid}",
                           affected_channels=[{"id":str(ch.id), "name":ch.name,
                                               "allow":str(ow.pair()[0].value),"deny":str(ow.pair()[1].value)}
                                              for ch, _, ow in targets],
                           changed=bool(targets))
        elif kind == "sync_channel":
            ch = target_channel(guild, a["channel_id"])
            if ch.category is None:
                raise ValueError(f"Cannot sync channel {ch.name} without category")
            changes_other_overrides = role_overwrite_snapshot(ch) != role_overwrite_snapshot(ch.category)
            if changes_other_overrides and not (destructive_sync and a.get("allow_overwrite_loss") is True):
                raise ValueError(f"Sync would erase custom overrides in {ch.name}; skipped. "
                                 "Requires explicit per-action allow_overwrite_loss and --allow-destructive-sync")
            details.update(label=f"Sync {ch.name} to {ch.category.name}", loses_custom_overrides=changes_other_overrides,
                           changed=not ch.permissions_synced)
        elif kind == "move_role_below":
            role = target_role(guild, a["role_id"], protected)
            anchor = guild.get_role(snowflake(a["anchor_role_id"], "anchor_role_id"))
            if anchor is None or role.id == anchor.id or role.managed or role.permissions.administrator:
                raise ValueError(f"Move role is invalid/protected/managed/admin: {role.name}")
            if anchor.position < 2:
                raise ValueError("Anchor is too low to move another role below")
            details.update(label=f"Move {role.name} below {anchor.name}", changed=role.position >= anchor.position,
                           before=role.position, anchor=anchor.position)
        elif kind == "delete_channel":
            ch = target_channel(guild, a["channel_id"])
            if ch.name != a["confirm_name"]:
                raise ValueError(f"Channel name mismatch: expected {a['confirm_name']!r}, got {ch.name!r}")
            if isinstance(ch, discord.CategoryChannel) and ch.channels:
                raise ValueError(f"Refuse to delete nonempty category {ch.name}: move/delete children explicitly")
            if not a.get("allow_delete", False):
                raise ValueError(f"Channel {ch.name}: explicit allow_delete:true required")
            details.update(label=f"PERMANENTLY delete channel {ch.name}", changed=True)
        planned.append(details)
    return planned


async def apply_action(guild, item, policy):
    """Revalidate high-risk predicates and make only the requested minimal edits."""
    a = item["source"]
    kind = a["type"]
    protected = {int(x) for x in policy.get("protected_role_ids", [])}
    reason = "ServerSentry one-shot fixer: " + str(a.get("reason", kind))[:400]
    if not item["changed"]:
        return "unchanged"
    if kind == "role_permissions":
        role = target_role(guild, a["role_id"], protected)
        if role.permissions.value != item["before"] or role.managed:
            raise RuntimeError("Role permissions changed after planning; abort")
        await role.edit(permissions=discord.Permissions(item["after"]), reason=reason)
    elif kind == "channel_role_permissions":
        ch = target_channel(guild, a["channel_id"])
        role = target_role(guild, a["role_id"], protected)
        old = ch.overwrites_for(role)
        if [x.value for x in old.pair()] != item["before"]:
            raise RuntimeError("Channel overwrite changed after planning; abort")
        new = discord.PermissionOverwrite.from_pair(*old.pair())
        for key, value in a["set"].items(): setattr(new, key, value)
        await ch.set_permissions(role, overwrite=new, reason=reason)
    elif kind == "mute_role_visibility":
        role = target_role(guild, a["role_id"], protected)
        if role.permissions.administrator:
            raise RuntimeError("Muted role gained Administrator; abort")
        allowed_ids = {int(x["id"]) for x in item["affected_channels"]}
        for ch in visible_channel_scope(guild):
            if ch.id not in allowed_ids: continue
            old = ch.overwrites_for(role)
            if old.view_channel is False: continue
            new = discord.PermissionOverwrite.from_pair(*old.pair())
            new.view_channel = False
            await ch.set_permissions(role, overwrite=new, reason=reason)
    elif kind == "cleanup_member_overrides":
        uid = int(a["user_id"])
        member = await guild.fetch_member(uid)
        expected = {int(x["id"]): x for x in item["affected_channels"]}
        current = member_override_targets(guild, uid)
        if {ch.id for ch, _, _ in current} != set(expected):
            raise RuntimeError("Member override set changed during execution; abort")
        for ch, _, ow in current:
            before = expected[ch.id]
            if str(ow.pair()[0].value) != before["allow"] or str(ow.pair()[1].value) != before["deny"]:
                raise RuntimeError("Member override changed during execution; abort")
            await ch.set_permissions(member, overwrite=None, reason=reason)
    elif kind == "sync_channel":
        ch = target_channel(guild, a["channel_id"])
        if ch.category is None:
            raise RuntimeError("Category removed; abort")
        if role_overwrite_snapshot(ch) != role_overwrite_snapshot(ch.category) and not a.get("allow_overwrite_loss"):
            raise RuntimeError("Special overrides found; refuse to sync")
        await ch.edit(sync_permissions=True, reason=reason)
    elif kind == "move_role_below":
        role = target_role(guild, a["role_id"], protected)
        anchor = guild.get_role(int(a["anchor_role_id"]))
        if anchor is None or role.managed or role.permissions.administrator:
            raise RuntimeError("Role/anchor changed; abort")
        if role.position != item["before"] or anchor.position != item["anchor"]:
            raise RuntimeError("Role positions changed after planning; abort")
        await role.edit(position=anchor.position-1, reason=reason)
    elif kind == "delete_channel":
        ch = target_channel(guild, a["channel_id"])
        if ch.name != a["confirm_name"] or (isinstance(ch, discord.CategoryChannel) and ch.channels):
            raise RuntimeError("Channel changed or category is not empty; abort")
        await ch.delete(reason=reason)
    return "applied"


def parse_args():
    p = argparse.ArgumentParser(description="ServerSentry one-shot fixer (preview by default)")
    p.add_argument("--policy", type=Path, required=True, help="Local JSON policy (NEVER commit real IDs)")
    p.add_argument("--apply", action="store_true", help="Write changes after a full backup and exact confirmation")
    p.add_argument("--allow-destructive-sync", action="store_true", help="Allow explicitly acknowledged loss of special overrides")
    p.add_argument("--allow-privilege-grants", action="store_true", help="Allow explicitly acknowledged privileged grants")
    return p.parse_args()


async def main():
    args = parse_args()
    try:
        policy = load_policy(args.policy)
        load_dotenv(HERE / ".env")
        token, guild_id = os.getenv("DISCORD_TOKEN", "").strip(), os.getenv("GUILD_ID", "").strip()
        if not token:
            raise ValueError("DISCORD_TOKEN is missing in local .env")
        snowflake(guild_id, "GUILD_ID")
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        return 2

    intents = discord.Intents.none()
    intents.guilds = True
    client = discord.Client(intents=intents)
    completed = False
    error = None

    @client.event
    async def on_ready():
        nonlocal completed, error
        if completed: return
        completed = True
        try:
            guild = client.get_guild(int(guild_id))
            if guild is None:
                raise RuntimeError("Server not found. Check GUILD_ID and bot membership")
            if not policy["actions"]:
                print("No actions defined in policy; nothing to change")
                return
            plan = make_plan(guild, policy, destructive_sync=args.allow_destructive_sync,
                             grants=args.allow_privilege_grants)
            for action in plan:
                status = "CHANGE" if action["changed"] else "NO-OP"
                print(f"[{status}] #{action['index']}: {action['label']} — {action['reason']}")
                if action.get("loses_custom_overrides"):
                    print("  WARNING: custom channel overrides will be replaced by category overrides!")
            preview = save_private_json(OUTPUT, "plan", {"guild_id":guild_id, "actions":plan})
            print("Plan written locally:", preview)
            if not args.apply:
                print("PREVIEW ONLY. Nothing was changed. Add --apply to execute.")
                return
            if not any(a["changed"] for a in plan):
                print("No changes needed")
                return
            phrase = f"APPLY {guild_id}"
            if input(f"Type exactly {phrase} to apply these changes: ").strip() != phrase:
                print("Cancelled; no changes")
                return
            backup = save_private_json(OUTPUT, "backup", guild_backup(guild))
            print("Backup written locally:", backup)
            for action in plan:
                result = await apply_action(guild, action, policy)
                print(f"  #{action['index']}: {result}")
            print("Finished. Run the audit again to verify the result.")
        except Exception as e:
            error = e
            print(f"FIXER ERROR: {type(e).__name__}: {e}", file=sys.stderr)
            print("If some operations succeeded, restore manually from local backup.", file=sys.stderr)
        finally:
            await client.close()

    try:
        async with client:
            await client.start(token, reconnect=False)
    except discord.LoginFailure:
        print("Invalid token. Rotate the token in Discord Developer Portal.", file=sys.stderr)
        return 1
    except discord.DiscordException as e:
        print(f"Discord connection error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 1 if error else 0


if __name__ == "__main__":
    try: sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("Cancelled")
        sys.exit(130)