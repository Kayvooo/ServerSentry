"""Ruleset 2 checks that operate on plain snapshot data (no Discord objects, no network).

Keeping the rules independent from discord.py makes them testable offline and reusable by
future front ends. Every rule is a risk signal: it never claims that a server is compromised and
never guesses intent from names.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable

# Permissions that let a holder reshape the server or its permission model.
SENSITIVE_GLOBAL = frozenset({"administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks"})
MODERATION = ("ban_members", "kick_members", "moderate_members", "mention_everyone", "view_audit_log",
              "manage_messages", "manage_nicknames", "manage_events", "manage_expressions")
BOT_IMPACT = frozenset({"ban_members", "kick_members", "moderate_members", "mention_everyone"})
CHANNEL_MANAGEMENT = ("manage_roles", "manage_webhooks", "manage_channels")
VOICE_MODERATION = ("mute_members", "deafen_members", "move_members")
WEAK_VERIFICATION = {"none": "warning", "low": "info"}

# Stable rule catalogue. `since` is the ruleset version that introduced the code.
RULE_INFO: dict[str, dict[str, Any]] = {
    "everyone_global_elevated": {"title": "@everyone has powerful server-wide permissions", "since": "1", "fixable": False},
    "elevated_role_review": {"title": "Role has powerful server-wide permissions", "since": "1", "fixable": True},
    "channel_obfuscated": {"title": "Channel not fully visible to the audit bot", "since": "1", "fixable": False},
    "conflicting_overwrite": {"title": "Conflicting channel override", "since": "1", "fixable": False},
    "sensitive_channel_visible_to_everyone": {"title": "Sensitively named channel visible to @everyone", "since": "1", "fixable": False},
    "everyone_channel_moderation": {"title": "@everyone has management permissions in a channel", "since": "1", "fixable": False},
    "individual_member_overrides": {"title": "Member-specific channel overrides", "since": "1", "fixable": False},
    "unsynced_channels": {"title": "Channels not synchronized with their category", "since": "1", "fixable": False},
    "audit_bot_admin": {"title": "Audit bot has Administrator", "since": "1", "fixable": False},
    "server_verification_low": {"title": "Low server verification level", "since": "2", "fixable": False},
    "server_content_filter_off": {"title": "Explicit media filter is off", "since": "2", "fixable": False},
    "server_mfa_not_required": {"title": "2FA is not required for moderation", "since": "2", "fixable": False},
    "role_hierarchy_escalation": {"title": "Role can assign more powerful roles", "since": "2", "fixable": False},
    "role_channel_management_override": {"title": "Role has channel management override", "since": "2", "fixable": True},
    "role_moderation_review": {"title": "Role has moderation permissions", "since": "2", "fixable": False},
    "everyone_channel_mention_everyone": {"title": "@everyone can mention everyone in a channel", "since": "2", "fixable": False},
    "everyone_voice_moderation": {"title": "@everyone can moderate voice members", "since": "2", "fixable": False},
    "announcement_open_posting": {"title": "@everyone can post in an announcement channel", "since": "2", "fixable": False},
    "expectation_violated": {"title": "Declared expectation is not met", "since": "2", "fixable": False},
    "expectation_unverifiable": {"title": "Declared expectation cannot be verified", "since": "2", "fixable": False},
}
# Evaluated on every audit. Expectation codes only count as checked when an expectations file was used.
OPTIONAL_CODES = ("expectation_violated", "expectation_unverifiable")
RULESET_2_CODES = tuple(code for code, info in RULE_INFO.items() if info["since"] == "2" and code not in OPTIONAL_CODES)


def _finding(severity: str, code: str, title: str, details: str, recommendation: str, **context: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "title": title, "details": details,
            "recommendation": recommendation, **context}


def _names(items: Iterable[str], limit: int = 5) -> str:
    items = list(items)
    shown = ", ".join(f"'{x}'" for x in items[:limit])
    return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _roles(snapshot: dict) -> list[dict]:
    return [r for r in snapshot["roles"] if not r.get("is_everyone")]


def _server_settings(snapshot: dict) -> list[dict]:
    settings = snapshot["server"].get("settings")
    if not isinstance(settings, dict):
        return []
    result = []
    verification = settings.get("verification_level")
    if verification in WEAK_VERIFICATION:
        result.append(_finding(
            WEAK_VERIFICATION[verification], "server_verification_low",
            f"Server verification level is '{verification}'",
            "New accounts can join and write immediately, which makes raids and spam easier.",
            "Consider a higher verification level unless the server is deliberately open."))
    if settings.get("explicit_content_filter") == "disabled":
        result.append(_finding(
            "info", "server_content_filter_off", "Explicit media filter is disabled",
            "Discord does not scan media from any member. This is intentional on some servers.",
            "Enable the filter at least for members without roles, unless this is a deliberate choice."))
    if settings.get("mfa_level") == "disabled":
        privileged = [r["name"] for r in _roles(snapshot)
                      if not r.get("managed") and SENSITIVE_GLOBAL & set(r.get("guild_permissions", []))]
        if privileged:
            result.append(_finding(
                "warning", "server_mfa_not_required", "2FA is not required for moderation actions",
                f"Roles with powerful permissions exist ({_names(privileged)}), but moderators do not need two-factor authentication.",
                "Enable 'Require 2FA for moderation' so a stolen password alone cannot manage the server."))
    return result


def _hierarchy(snapshot: dict) -> list[dict]:
    result = []
    roles = [r for r in _roles(snapshot) if not r.get("managed")]
    for role in roles:
        held = set(role.get("guild_permissions", []))
        if "manage_roles" not in held or "administrator" in held:
            continue
        gains: dict[str, list[str]] = {}
        for lower in roles:
            if lower["position"] >= role["position"]:
                continue
            extra = (SENSITIVE_GLOBAL & set(lower.get("guild_permissions", []))) - held
            if extra:
                gains[lower["name"]] = sorted(extra)
        if not gains:
            continue
        critical = any("administrator" in perms for perms in gains.values())
        lines = "; ".join(f"'{name}' ({', '.join(perms)})" for name, perms in list(gains.items())[:5])
        more = f" and {len(gains) - 5} more" if len(gains) > 5 else ""
        result.append(_finding(
            "critical" if critical else "warning", "role_hierarchy_escalation",
            f"Role '{role['name']}' can assign more powerful roles",
            f"Members with Manage Roles can generally assign roles below their own highest role. Below "
            f"'{role['name']}': {lines}{more}. Holders could grant these permissions to themselves or others.",
            "Move the powerful roles above this role, or remove Manage Roles from it. Verify the hierarchy in Discord.",
            role_id=role["id"]))
    return result


def _channel_index(snapshot: dict) -> dict[str, dict]:
    return {c["id"]: c for c in snapshot["channels"] if not c.get("obfuscated")}


def _covered_by_category(channel: dict, index: dict[str, dict], flag_check: Callable[[dict], bool]) -> bool:
    """A synced child repeats its category; report the category once instead of every child."""
    parent = index.get(channel.get("category_id") or "")
    return bool(channel.get("permissions_synced") and parent and flag_check(parent))


def _channel_overrides(snapshot: dict) -> list[dict]:
    result = []
    index, server_id = _channel_index(snapshot), snapshot["server"]["id"]
    roles = {r["id"]: r for r in snapshot["roles"]}

    def has_override(channel: dict) -> bool:
        return any(ow["target_type"] == "role" and set(ow["allow"]) & set(CHANNEL_MANAGEMENT)
                   for ow in channel.get("permission_overwrites", []))
    for channel in index.values():
        if _covered_by_category(channel, index, has_override):
            continue
        for ow in channel.get("permission_overwrites", []):
            role = roles.get(ow["target_id"]) if ow["target_type"] == "role" else None
            if role is None or ow["target_id"] == server_id or "administrator" in role.get("guild_permissions", []):
                continue
            granted = [p for p in CHANNEL_MANAGEMENT if p in ow["allow"]]
            if not granted:
                continue
            kind = "Bot role" if role.get("managed") else "Role"
            label = f"#{channel.get('name', 'channel')}"
            result.append(_finding(
                "warning", "role_channel_management_override",
                f"{kind} '{role['name']}' has management overrides in {label}",
                f"The channel override allows: {', '.join(granted)}. Manage Roles/Webhooks/Channels in a channel "
                "lets holders change access or post through webhooks there.",
                "Remove the override if it is not required for this channel.",
                role_id=role["id"], channel_id=channel["id"], permissions=granted))
    return result


def _role_moderation(snapshot: dict) -> list[dict]:
    result = []
    for role in _roles(snapshot):
        held = set(role.get("guild_permissions", []))
        if SENSITIVE_GLOBAL & held:
            continue  # Already covered by elevated_role_review.
        found = [p for p in MODERATION if p in held]
        if not found:
            continue
        managed = bool(role.get("managed"))
        severity = "warning" if managed and BOT_IMPACT & held else "info"
        kind = "Bot/integration role" if managed else "Role"
        extra = " A leaked bot token would inherit these permissions." if managed else ""
        result.append(_finding(
            severity, "role_moderation_review", f"{kind} '{role['name']}' has moderation permissions",
            f"Permissions: {', '.join(found)}.{extra}",
            "Confirm this role is assigned only to trusted members or bots.", role_id=role["id"]))
    return result


def _everyone_channels(snapshot: dict) -> list[dict]:
    result = []
    index = _channel_index(snapshot)
    everyone = next((r for r in snapshot["roles"] if r.get("is_everyone")), None)
    global_flags = set(everyone.get("guild_permissions", [])) if everyone else set()
    for channel in index.values():
        eff = channel.get("everyone_effective_permissions")
        if not isinstance(eff, dict) or not eff.get("view_channel"):
            continue
        label = f"#{channel.get('name', 'channel')}"
        ref = {"channel_id": channel["id"]}
        if eff.get("mention_everyone") and "mention_everyone" not in global_flags and not _covered_by_category(
                channel, index, lambda p: bool((p.get("everyone_effective_permissions") or {}).get("mention_everyone"))):
            result.append(_finding(
                "warning", "everyone_channel_mention_everyone", f"@everyone can mention everyone in {label}",
                "A channel override allows @everyone to ping @everyone/@here, which enables mass notifications.",
                "Deny Mention Everyone for @everyone here unless it is intentional.", **ref))
        voice = [p for p in VOICE_MODERATION if eff.get(p)]
        if voice and not _covered_by_category(
                channel, index, lambda p: any((p.get("everyone_effective_permissions") or {}).get(x) for x in VOICE_MODERATION)):
            result.append(_finding(
                "warning", "everyone_voice_moderation", f"@everyone can moderate voice members in {label}",
                "Effective permissions (@everyone only): " + ", ".join(voice),
                "Remove these voice moderation permissions from @everyone unless the channel is deliberately self-moderated.",
                **ref))
        if channel.get("type") == "news" and eff.get("send_messages"):
            result.append(_finding(
                "warning", "announcement_open_posting", f"@everyone can post in announcement channel {label}",
                "Announcement channels normally restrict posting; messages here can be published to followers.",
                "Deny Send Messages for @everyone and allow only the roles that publish announcements.", **ref))
    return result


RULES: tuple[Callable[[dict], list[dict]], ...] = (
    _server_settings, _hierarchy, _channel_overrides, _role_moderation, _everyone_channels,
)


def evaluate_rules(snapshot: dict) -> list[dict]:
    """Return ruleset-2 findings for a snapshot-shaped dict with server, roles and channels."""
    findings: list[dict] = []
    for rule in RULES:
        findings.extend(rule(snapshot))
    return findings
