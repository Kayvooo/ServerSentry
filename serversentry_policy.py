"""User-declared expectations and time-limited accepted risks. Standard library only.

An expectation states what the *administrator* intends ("this role never has Manage Roles"). The
tool then reports violations. Nothing is inferred from names. An accepted risk never deletes a
finding: it stays in the data, is marked with a reason and an expiry date, and reopens on its own.
"""
from __future__ import annotations

from copy import deepcopy
from collections import Counter
from datetime import date, datetime
import difflib
import json
from pathlib import Path
from typing import Any

SEVERITIES = ("critical", "warning", "info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
SERVER_SETTINGS = {
    "verification_level": ("none", "low", "medium", "high", "highest"),
    "explicit_content_filter": ("disabled", "no_role", "all_members"),
    "mfa_level": ("disabled", "require_2fa"),
    "default_notifications": ("all_messages", "only_mentions"),
}
# Kept static so offline commands need no discord.py; tests compare both tables with discord.py.
# discord.py reports one canonical name per permission bit (for example `read_messages` for View Channel),
# so snapshots contain canonical names while people naturally write the Discord UI names.
PERMISSION_ALIASES = {
    "view_channel": "read_messages", "use_external_emojis": "external_emojis", "manage_permissions": "manage_roles",
    "manage_emojis": "manage_expressions", "manage_emojis_and_stickers": "manage_expressions",
    "use_external_stickers": "external_stickers", "create_polls": "send_polls",
}
CANONICAL_PERMISSIONS = frozenset({
    "add_reactions", "administrator", "attach_files", "ban_members", "bypass_slowmode", "change_nickname", "connect",
    "create_events", "create_expressions", "create_instant_invite", "create_private_threads", "create_public_threads",
    "deafen_members", "embed_links", "external_emojis", "external_stickers", "kick_members", "manage_channels",
    "manage_events", "manage_expressions", "manage_guild", "manage_messages", "manage_nicknames", "manage_roles",
    "manage_threads", "manage_webhooks", "mention_everyone", "moderate_members", "move_members", "mute_members",
    "pin_messages", "priority_speaker", "read_message_history", "read_messages", "request_to_speak", "send_messages",
    "send_messages_in_threads", "send_polls", "send_tts_messages", "send_voice_messages", "set_voice_channel_status",
    "speak", "stream", "use_application_commands", "use_embedded_activities", "use_external_apps",
    "use_external_sounds", "use_soundboard", "use_voice_activation", "view_audit_log",
    "view_creator_monetization_analytics", "view_guild_insights",
})
KNOWN_PERMISSIONS = CANONICAL_PERMISSIONS | frozenset(PERMISSION_ALIASES)


def canonical(name: str) -> str:
    return PERMISSION_ALIASES.get(name, name)


EXPECTATION_TYPES = ("role_must_lack", "permission_allowlist", "channel_visible_only_to", "server_setting_in")
EXPECTATION_CODES = ("expectation_violated", "expectation_unverifiable")
EXPIRY_WARNING_DAYS = 30


def _snowflake(value: Any, label: str) -> str:
    if type(value) is not str or not value.isdecimal():
        raise ValueError(f"{label} must be a numeric Discord ID written as a string")
    return value


def _permissions(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(type(x) is not str for x in value):
        raise ValueError(f"{label} must be a non-empty list of permission names")
    for name in value:
        if name not in KNOWN_PERMISSIONS:
            hint = difflib.get_close_matches(name, sorted(KNOWN_PERMISSIONS), n=1)
            raise ValueError(f"{label}: unknown permission '{name}'" + (f" (did you mean '{hint[0]}'?)" if hint else ""))
    return list(dict.fromkeys(value))


def _ids(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(type(x) is not str for x in value):
        raise ValueError(f"{label} must be a list of numeric ID strings")
    return [_snowflake(x, label) for x in value]


def _parse_day(value: Any, label: str) -> date:
    if type(value) is not str:
        raise ValueError(f"{label} must be a date written as YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid date written as YYYY-MM-DD") from exc


def validate_expectations(data: Any) -> dict:
    """Validate the whole file up front so a typo never silently disables a check."""
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("Expectations file must be an object with version: 1")
    unknown = set(data) - {"version", "expectations", "accepted_risks", "_comment"}
    if unknown:
        raise ValueError(f"Unknown top-level keys: {', '.join(sorted(unknown))}")
    expectations, accepted = data.get("expectations", []), data.get("accepted_risks", [])
    if not isinstance(expectations, list) or not isinstance(accepted, list):
        raise ValueError("expectations and accepted_risks must be arrays")
    seen: set[str] = set()
    from serversentry_rules import RULE_INFO
    for number, item in enumerate(expectations, 1):
        label = f"Expectation {number}"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        identifier = item.get("id")
        if type(identifier) is not str or not identifier.strip() or len(identifier) > 80:
            raise ValueError(f"{label}: id must be a short, non-empty string")
        if identifier in seen:
            raise ValueError(f"{label}: duplicate id '{identifier}'")
        seen.add(identifier)
        label = f"Expectation '{identifier}'"
        kind = item.get("type")
        if kind not in EXPECTATION_TYPES:
            raise ValueError(f"{label}: type must be one of {', '.join(EXPECTATION_TYPES)}")
        if item.get("severity", "warning") not in SEVERITIES:
            raise ValueError(f"{label}: severity must be critical, warning or info")
        if "reason" in item and type(item["reason"]) is not str:
            raise ValueError(f"{label}: reason must be a string")
        allowed = {"id", "type", "severity", "reason"}
        if kind == "role_must_lack":
            allowed |= {"role_id", "permissions"}
            _snowflake(item.get("role_id"), f"{label}: role_id")
            _permissions(item.get("permissions"), f"{label}: permissions")
        elif kind == "permission_allowlist":
            allowed |= {"permission", "role_ids"}
            _permissions([item.get("permission")], f"{label}: permission")
            _ids(item.get("role_ids"), f"{label}: role_ids")
        elif kind == "channel_visible_only_to":
            allowed |= {"channel_id", "role_ids"}
            _snowflake(item.get("channel_id"), f"{label}: channel_id")
            _ids(item.get("role_ids"), f"{label}: role_ids")
        else:
            allowed |= {"setting", "allowed"}
            setting = item.get("setting")
            if setting not in SERVER_SETTINGS:
                raise ValueError(f"{label}: setting must be one of {', '.join(SERVER_SETTINGS)}")
            values = item.get("allowed")
            if (not isinstance(values, list) or not values
                    or any(v not in SERVER_SETTINGS[setting] for v in values)):
                raise ValueError(f"{label}: allowed must list values from {', '.join(SERVER_SETTINGS[setting])}")
        extra = set(item) - allowed
        if extra:
            raise ValueError(f"{label}: unknown keys {', '.join(sorted(extra))}")
    for number, item in enumerate(accepted, 1):
        label = f"Accepted risk {number}"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        if item.get("code") not in RULE_INFO:
            raise ValueError(f"{label}: code must be a known rule code (see docs/rules.md)")
        for key in ("role_id", "channel_id"):
            if key in item:
                _snowflake(item[key], f"{label}: {key}")
        if "target" in item and type(item["target"]) is not str:
            raise ValueError(f"{label}: target must be a string")
        if type(item.get("reason")) is not str or not item["reason"].strip():
            raise ValueError(f"{label}: a reason is required")
        _parse_day(item.get("expires"), f"{label}: expires")
        extra = set(item) - {"code", "role_id", "channel_id", "target", "reason", "expires"}
        if extra:
            raise ValueError(f"{label}: unknown keys {', '.join(sorted(extra))}")
    return data


def load_expectations(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read expectations {path}: {exc}") from exc
    return validate_expectations(data)


def _finding(severity: str, code: str, title: str, details: str, recommendation: str, **context: Any) -> dict:
    return {"severity": severity, "code": code, "title": title, "details": details,
            "recommendation": recommendation, **context}


def _why(item: dict) -> str:
    return f" Why: {item['reason']}" if item.get("reason") else ""


def _unverifiable(item: dict, what: str) -> dict:
    return _finding(
        "warning", "expectation_unverifiable", f"Expectation '{item['id']}' cannot be verified",
        f"{what} Check the ID or rerun the audit with a bot that can see it.{_why(item)}",
        "Fix the expectation or the audit scope. A check that cannot run is not a passing check.",
        target=f"expect:{item['id']}")


def _check(item: dict, snapshot: dict) -> list[dict]:
    severity, target = item.get("severity", "warning"), f"expect:{item['id']}"
    roles = {r["id"]: r for r in snapshot["roles"]}
    channels = {c["id"]: c for c in snapshot["channels"]}
    server_id = snapshot["server"]["id"]
    kind = item["type"]
    if kind == "role_must_lack":
        role = roles.get(item["role_id"])
        if role is None or "guild_permissions" not in role:
            return [_unverifiable(item, f"Role {item['role_id']} is not in the scan.")]
        held = {canonical(p) for p in role["guild_permissions"]}
        found = [p for p in item["permissions"] if canonical(p) in held]
        if not found:
            return []
        return [_finding(
            severity, "expectation_violated", f"'{role['name']}' has permissions it must not have",
            f"Expectation '{item['id']}': the role has {', '.join(found)}.{_why(item)}",
            "Revoke these permissions, or change the expectation if your intent changed.",
            role_id=role["id"], target=target)]
    if kind == "permission_allowlist":
        permission, allowed = item["permission"], set(item["role_ids"])
        wanted = canonical(permission)
        if any("guild_permissions" not in r for r in snapshot["roles"]):
            return [_unverifiable(item, "The snapshot does not record role permissions.")]
        return [_finding(
            severity, "expectation_violated",
            f"'{role['name']}' holds {permission} but is not on the allowlist",
            f"Expectation '{item['id']}': only {len(allowed)} listed role(s) may hold {permission}.{_why(item)}",
            "Revoke the permission from this role, or add the role to the allowlist if it is intended.",
            role_id=role["id"], target=target)
            for role in snapshot["roles"]
            if wanted in {canonical(p) for p in role["guild_permissions"]} and role["id"] not in allowed]
    if kind == "channel_visible_only_to":
        channel = channels.get(item["channel_id"])
        if channel is None or channel.get("obfuscated") or "single_role_permission_matrix" not in channel:
            return [_unverifiable(item, f"Channel {item['channel_id']} is missing, hidden or has no recorded permissions.")]
        name = channel.get("name", "channel")
        if (channel.get("everyone_effective_permissions") or {}).get("view_channel"):
            return [_finding(
                severity, "expectation_violated", f"#{name} is visible to @everyone",
                f"Expectation '{item['id']}': this channel should be visible only to the listed roles.{_why(item)}",
                "Deny View Channel for @everyone on this channel or its category.",
                channel_id=channel["id"], role_id=server_id, target=target)]
        allowed = set(item["role_ids"])
        return [_finding(
            severity, "expectation_violated", f"'{roles[row['role_id']]['name'] if row['role_id'] in roles else row['role_id']}' can view #{name}",
            f"Expectation '{item['id']}': this role is not on the visibility list.{_why(item)} "
            "Roles with Administrator always see every channel and are reviewed by the elevated-role rule.",
            "Deny View Channel for this role here, or add it to the expectation if the access is intended.",
            channel_id=channel["id"], role_id=row["role_id"], target=target)
            for row in channel["single_role_permission_matrix"]
            if row["permissions"].get("view_channel") and row["role_id"] not in allowed
            and "administrator" not in roles.get(row["role_id"], {}).get("guild_permissions", [])]
    value = (snapshot["server"].get("settings") or {}).get(item["setting"])
    if value is None:
        return [_unverifiable(item, f"The snapshot does not record the server setting '{item['setting']}'.")]
    if value in item["allowed"]:
        return []
    return [_finding(
        severity, "expectation_violated", f"Server setting {item['setting']} is '{value}'",
        f"Expectation '{item['id']}': allowed values are {', '.join(item['allowed'])}.{_why(item)}",
        "Change the server setting in Discord, or adjust the expectation.", target=target)]


def _scan_day(snapshot: dict) -> date:
    stamp = str(snapshot["audit"].get("generated_at_utc", ""))
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).date()
    except ValueError:
        return date.today()


def _matches(entry: dict, finding: dict) -> bool:
    return finding["code"] == entry["code"] and all(
        finding.get(key) == entry[key] for key in ("role_id", "channel_id", "target") if key in entry)


def apply_policy(snapshot: dict, policy: dict | None, *, fresh: bool = False) -> dict:
    """Return a copy with expectation findings, accepted-risk marks and a policy summary.

    Expiry is judged on the scan date, so re-rendering an old report never changes its meaning.
    `fresh` marks the output of a live audit in this process, whose rule coverage is fully known.
    Older exports without recorded coverage never get coverage invented for them.
    """
    if not policy:
        return snapshot
    validate_expectations(policy)
    result = deepcopy(snapshot)
    # Idempotent: a snapshot saved by a live audit already contains findings from an earlier evaluation.
    result["findings"] = [f for f in result["findings"] if f["code"] not in EXPECTATION_CODES]
    expectations = policy.get("expectations", [])
    for item in expectations:
        result["findings"].extend(_check(item, result))
    if expectations and (fresh or "rules_checked" in result["audit"]):
        checked = result["audit"].setdefault("rules_checked", [])
        checked.extend(code for code in EXPECTATION_CODES if code not in checked)
    today = _scan_day(result)
    used: set[int] = set()
    expired, accepted_count = [], 0
    for finding in result["findings"]:
        finding.pop("accepted", None)
        finding.pop("acceptance_expired", None)
        for index, entry in enumerate(policy.get("accepted_risks", [])):
            if not _matches(entry, finding):
                continue
            used.add(index)
            expires = _parse_day(entry["expires"], "expires")
            mark = {"reason": entry["reason"], "expires": entry["expires"]}
            if expires >= today:
                finding["accepted"] = mark
                accepted_count += 1
            else:
                finding["acceptance_expired"] = mark
                expired.append({"code": finding["code"], **{k: finding[k] for k in ("role_id", "channel_id") if k in finding},
                                **mark})
            break
    entries = policy.get("accepted_risks", [])
    soon = [dict(e) for i, e in enumerate(entries) if i in used
            and 0 <= (_parse_day(e["expires"], "expires") - today).days <= EXPIRY_WARNING_DAYS]
    result["findings"].sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["code"], f["title"]))
    result["summary"] = dict(Counter(f["severity"] for f in result["findings"] if "accepted" not in f))
    result["policy"] = {
        "as_of": today.isoformat(), "expectations_evaluated": len(expectations),
        "accepted_count": accepted_count, "expired": expired, "expiring_soon": soon,
        "unused_acceptances": [dict(e) for i, e in enumerate(entries) if i not in used],
    }
    return result
