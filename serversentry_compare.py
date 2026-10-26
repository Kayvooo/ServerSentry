"""Offline semantic comparison, with conservative treatment of missing coverage."""
from __future__ import annotations

from collections import Counter, defaultdict
import json

from serversentry_snapshots import validate_snapshot

STATUS_LABELS = {
    "newly_reported": "Newly reported", "persistent": "Still reported",
    "severity_changed": "Severity changed", "no_longer_detected": "No longer detected",
    "not_checked": "Cannot verify", "target_removed": "Role removed",
    "not_comparable": "Member aliases cannot be compared",
}
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _role_state(role: dict) -> dict:
    fields = ("name", "position", "managed", "bot_managed", "mentionable", "hoist", "is_everyone")
    state = {key: role[key] for key in fields if key in role}
    # Names, not redundant bitfields; ordering is irrelevant.
    if "guild_permissions" in role:
        state["guild_permissions"] = sorted(role["guild_permissions"])
    return state


def _channel_state(channel: dict) -> dict:
    fields = ("name", "type", "position", "category_id", "permissions_synced", "obfuscated",
              "everyone_effective_permissions", "member_override_count")
    state = {key: channel[key] for key in fields if key in channel}
    if "permission_overwrites" in channel:
        state["role_overwrites"] = {
            ow["target_id"]: {"allow": sorted(ow["allow"]), "deny": sorted(ow["deny"])}
            for ow in channel["permission_overwrites"] if ow["target_type"] == "role"
        }
        # Only aggregate patterns: member_N identifies different people across runs.
        patterns = Counter(json.dumps({"allow": sorted(ow["allow"]), "deny": sorted(ow["deny"])},
                                      sort_keys=True)
                           for ow in channel["permission_overwrites"] if ow["target_type"] == "member")
        state["member_overwrite_patterns_aggregate_only"] = dict(sorted(patterns.items()))
    if "single_role_permission_matrix" in channel:
        state["single_role_permissions"] = {
            row["role_id"]: row["permissions"] for row in channel["single_role_permission_matrix"]
            if "role_id" in row and "permissions" in row
        }
    return state


def _object_changes(before: dict, after: dict, collection: str) -> list[dict]:
    old = {x["id"]: x for x in before[collection]}
    new = {x["id"]: x for x in after[collection]}
    result = []
    convert = _role_state if collection == "roles" else _channel_state
    for identifier in sorted(old.keys() | new.keys()):
        left, right = old.get(identifier), new.get(identifier)
        item = {"kind": collection[:-1], "id": identifier,
                "name": (right or left).get("name", "Hidden channel")}
        if left is None:
            result.append({**item, "status": "added", "fields": [], "before": None, "after": convert(right)})
        elif right is None:
            status = "removed" if collection == "roles" else "removed_or_unavailable"
            result.append({**item, "status": status, "fields": [], "before": convert(left), "after": None})
        elif collection == "channels" and (left.get("obfuscated") or right.get("obfuscated")):
            result.append({**item, "status": "not_comparable", "fields": ["coverage"],
                           "before": {"obfuscated": left.get("obfuscated", False)},
                           "after": {"obfuscated": right.get("obfuscated", False)}})
        else:
            ls, rs = convert(left), convert(right)
            fields = sorted(k for k in ls.keys() | rs.keys() if ls.get(k) != rs.get(k))
            if fields:
                result.append({**item, "status": "changed", "fields": fields,
                               "before": {k: ls.get(k) for k in fields},
                               "after": {k: rs.get(k) for k in fields}})
    return result


def _finding_key(finding: dict) -> tuple:
    target = finding.get("target", "")
    # Aggregate unstable aliases within a channel; do not match individual people.
    target = "member_*" if target.startswith("member_") else target
    return (finding["code"], finding.get("role_id", ""), finding.get("channel_id", ""), target)


def _groups(snapshot: dict) -> dict:
    result = defaultdict(list)
    for finding in snapshot["findings"]:
        result[_finding_key(finding)].append(finding)
    return result


def _severity(findings: list[dict]) -> str | None:
    return min((x["severity"] for x in findings), key=SEVERITY_ORDER.get, default=None)


def _missing_status(key: tuple, before: dict, after: dict) -> tuple[str, str]:
    code, role_id, channel_id, target = key
    if not role_id and target in {r["id"] for r in before["roles"]}:
        role_id = target
    roles = {r["id"] for r in after["roles"]}
    channels = {c["id"]: c for c in after["channels"]}
    if role_id and role_id not in roles:
        return "target_removed", "The role is no longer in the role inventory; this is not a repaired permission."
    if channel_id and (channel_id not in channels or channels[channel_id].get("obfuscated")):
        return "not_checked", "Channel is missing or hidden. Removal and lost visibility cannot be distinguished."
    audits = (before["audit"], after["audit"])
    if (not audits[0].get("ruleset_version")
            or audits[0].get("ruleset_version") != audits[1].get("ruleset_version")
            or any(code not in a.get("rules_checked", []) for a in audits)):
        return "not_checked", "Legacy export, changed ruleset or missing rule coverage; absence is not proof of a fix."
    if code == "unsynced_channels" and (
        {c["id"] for c in before["channels"]} != set(channels)
        or any(c.get("obfuscated") for s in (before, after) for c in s["channels"])
    ):
        return "not_checked", "Channel inventory or visibility changed; aggregate findings cannot be verified."
    return "no_longer_detected", "Not detected by the same rule in the recorded scope. This is not a full security guarantee."


def compare_snapshots(before: dict, after: dict) -> dict:
    validate_snapshot(before)
    validate_snapshot(after)
    if before["server"]["id"] != after["server"]["id"]:
        raise ValueError("Cannot compare snapshots from different servers")
    old, new = _groups(before), _groups(after)
    findings = []
    for key in sorted(old.keys() | new.keys()):
        left, right = old.get(key, []), new.get(key, [])
        note = ""
        if key[3] == "member_*":
            status = "not_comparable"
            note = "Member aliases are assigned per scan; compare channel-level counts and patterns only."
        elif not left:
            status = "newly_reported"
            note = "Reported in this scan, absent in the baseline; may also reflect better visibility or changed rules."
        elif not right:
            status, note = _missing_status(key, before, after)
        elif _severity(left) != _severity(right):
            status = "severity_changed"
        else:
            status = "persistent"
        findings.append({"code": key[0], "role_id": key[1], "channel_id": key[2],
                         "status": status, "note": note, "before": left, "after": right,
                         "severity_before": _severity(left), "severity_after": _severity(right)})
    warnings = [
        "Findings are risk signals, not confirmed vulnerabilities. No Discord changes were made.",
        "Missing channels may be deleted or unavailable. They are never automatically counted as fixed.",
        "Member aliases cannot identify the same member across scans; only aggregate overwrite patterns are compared.",
        "A single-role matrix is not a member permission check. Private threads and message content are not inspected.",
    ]
    if any("schema_version" not in s["audit"] for s in (before, after)):
        warnings.append("Legacy snapshot: historical rule coverage was not recorded; missing findings remain unverified.")
    if before["audit"].get("ruleset_version") != after["audit"].get("ruleset_version"):
        warnings.append("Ruleset changed; findings may differ because checks changed.")
    return {
        "comparison_version": 1, "server": after["server"],
        "before": {k: before["audit"].get(k) for k in ("scan_id", "generated_at_utc", "ruleset_version")},
        "after": {k: after["audit"].get(k) for k in ("scan_id", "generated_at_utc", "ruleset_version")},
        "findings": findings,
        "changes": _object_changes(before, after, "roles") + _object_changes(before, after, "channels"),
        "summary": dict(Counter(f["status"] for f in findings)), "limitations": warnings,
    }
