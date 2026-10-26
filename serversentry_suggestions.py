"""Offline, selected revocation proposals; no Discord dependency or inferred fixes."""
from __future__ import annotations

from serversentry_snapshots import validate_snapshot

REVIEW_PERMISSIONS = {"manage_guild", "manage_roles", "manage_channels", "manage_webhooks"}


def candidates(snapshot: dict, protected_ids=()) -> tuple[list[dict], list[str]]:
    validate_snapshot(snapshot)
    if any(not str(x).isdecimal() or not 15 <= len(str(x)) <= 21 for x in protected_ids):
        raise ValueError("Protected roles need numeric Discord snowflake IDs")
    roles = {r["id"]: r for r in snapshot["roles"]}
    protected = set(map(str, protected_ids)) | {
        r["id"] for r in snapshot["roles"] if "administrator" in r.get("guild_permissions", [])
    }
    options, skipped = [], []
    for number, finding in enumerate(snapshot["findings"], 1):
        role = roles.get(finding.get("role_id"))
        if finding["code"] != "elevated_role_review" or role is None:
            skipped.append(f"#{number}: unsupported finding; review manually")
            continue
        identifier = role["id"]
        if (identifier == snapshot["server"]["id"] or identifier in protected or role.get("managed")
                or not 15 <= len(identifier) <= 21):
            skipped.append(f"#{number}: protected, managed, default or synthetic role; no proposal")
            continue
        permissions = sorted(REVIEW_PERMISSIONS & set(role.get("guild_permissions", [])))
        if permissions:
            options.append({"number": number, "role_id": identifier, "name": role["name"], "permissions": permissions})
    return options, skipped


def suggest_policy(snapshot: dict, selections: dict[int, list[str]], protected_ids=()) -> dict:
    if not 15 <= len(snapshot["server"]["id"]) <= 21:
        raise ValueError("A runnable suggestion needs a real-format server ID, not a short synthetic ID")
    options, _ = candidates(snapshot, protected_ids)
    by_number = {o["number"]: o for o in options}
    if not selections or any(number not in by_number for number in selections):
        raise ValueError("Select supported finding numbers from the displayed list")
    actions = []
    for number, flags in selections.items():
        choice = by_number[number]
        if not flags or not set(flags) <= set(choice["permissions"]):
            raise ValueError(f"Finding #{number}: choose only listed permissions to revoke")
        actions.append({"type": "role_permissions", "role_id": choice["role_id"], "revoke": sorted(set(flags)),
                        "reason": f"Explicitly selected revocation for audit finding {number}"})
    protected = set(map(str, protected_ids)) | {
        r["id"] for r in snapshot["roles"] if "administrator" in r.get("guild_permissions", [])
    }
    return {"version": 1, "guild_id": snapshot["server"]["id"],
            "protected_role_ids": sorted(protected), "actions": actions}


def interactive_suggestion(snapshot: dict, *, selected=None, revoke=None, protected_ids=(), ask=input) -> dict:
    options, skipped = candidates(snapshot, protected_ids)
    for option in options:
        print(f"#{option['number']}: {option['name']} — review {', '.join(option['permissions'])}")
    for note in skipped: print("MANUAL:", note)
    if not options:
        raise ValueError("No supported revocation proposals. No policy was written")
    text = selected if selected is not None else ask("Finding numbers to review (comma separated): ")
    try:
        numbers = [int(x.strip()) for x in text.split(",")]
    except ValueError as exc:
        raise ValueError("Choose comma-separated finding numbers") from exc
    if len(set(numbers)) != len(numbers):
        raise ValueError("Choose each finding only once")
    choices = {}
    for number in numbers:
        if number not in {o["number"] for o in options}:
            raise ValueError(f"Finding #{number} is not a supported proposal")
        text = revoke if revoke is not None else ask(f"Permissions to REVOKE for finding #{number} (comma separated): ")
        choices[number] = [x.strip() for x in text.split(",") if x.strip()]
    return suggest_policy(snapshot, choices, protected_ids)
