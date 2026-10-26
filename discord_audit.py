#!/usr/bin/env python3
"""Read-only Discord role/channel permission audit. Does not read messages or change server settings."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sys
from typing import Any

import discord
from dotenv import load_dotenv

from serversentry_report import render_html
from serversentry_snapshots import prepare_snapshot, save_audit_bundle

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "audit_output"

# Permissions worth showing for the effective single-role view of each channel.
CHANNEL_PERMISSION_KEYS = (
    "view_channel", "send_messages", "read_message_history", "send_messages_in_threads",
    "create_public_threads", "create_private_threads", "manage_threads",
    "manage_messages", "manage_channels", "manage_webhooks", "manage_roles",
    "mention_everyone", "attach_files", "connect", "speak", "stream",
    "move_members", "mute_members", "deafen_members",
)
HIGH_RISK_GLOBAL = (
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "manage_webhooks", "ban_members", "kick_members", "moderate_members",
    "manage_messages", "mention_everyone", "view_audit_log",
)
CRITICAL_EVERYONE = {"administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks"}
SENSITIVE_GLOBAL_ROLE_PERMISSIONS = {
    "administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks",
}
SENSITIVE_CHANNEL_PERMISSIONS = ("manage_channels", "manage_webhooks", "manage_roles", "manage_messages")
# These are deliberately only *hints*. A channel's purpose cannot be inferred from its name alone.
SENSITIVE_NAME_RE = re.compile(
    r"(?:^|[\s._-])(admin|admins|staff|moderation|moderator|mods?|intern|internal|"
    r"privat|private|sicherheit|security|audit|logs?|teamleitung|management|"
    r"bewerbungen?|applications?)(?=$|[\s._-])",
    re.IGNORECASE,
)
OBFUSCATED_FLAG = 1 << 17  # Discord channel metadata may be hidden from the bot.


def enabled_permissions(permissions: discord.Permissions) -> list[str]:
    return sorted(name for name, allowed in permissions if allowed)


def one_role_permissions(channel: discord.abc.GuildChannel, role: discord.Role) -> dict[str, bool]:
    # Applies @everyone + this one role + their channel overwrites.
    # This is not an effective permission check for a member with several roles.
    effective = channel.permissions_for(role)
    return {name: bool(getattr(effective, name, False)) for name in CHANNEL_PERMISSION_KEYS}


def add_finding(
    findings: list[dict[str, Any]], severity: str, code: str, title: str,
    details: str, recommendation: str, **context: Any,
) -> None:
    findings.append({
        "severity": severity, "code": code, "title": title,
        "details": details, "recommendation": recommendation, **context,
    })


def audit_guild(guild: discord.Guild) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    member_aliases: dict[int, str] = {}  # Raw member IDs and usernames are NOT exported.
    default_role = guild.default_role

    roles = sorted(guild.roles, key=lambda r: (r.position, r.id), reverse=True)
    exported_roles: list[dict[str, Any]] = []
    for role in roles:
        active = enabled_permissions(role.permissions)
        exported_roles.append({
            "id": str(role.id), "name": role.name, "position": role.position,
            "is_everyone": role.is_default(), "managed": role.managed,
            "bot_managed": role.is_bot_managed(), "mentionable": role.mentionable,
            "hoist": role.hoist, "guild_permissions": active,
            "guild_permissions_bitfield": str(role.permissions.value),
        })
        if role.is_default():
            risky = [name for name in HIGH_RISK_GLOBAL if getattr(role.permissions, name, False)]
            if risky:
                severity = "critical" if any(p in CRITICAL_EVERYONE for p in risky) else "warning"
                add_finding(
                    findings, severity, "everyone_global_elevated",
                    "@everyone has powerful server-wide permissions",
                    "@everyone permissions: " + ", ".join(risky),
                    "Grant @everyone only the permissions that are explicitly needed.",
                    role_id=str(role.id),
                )
        else:
            sensitive = [p for p in sorted(SENSITIVE_GLOBAL_ROLE_PERMISSIONS) if getattr(role.permissions, p, False)]
            if sensitive:
                add_finding(
                    findings, "warning", "elevated_role_review",
                    f"Role '{role.name}' has powerful permissions",
                    "Server permissions: " + ", ".join(sensitive) + (". Administrator bypasses channel restrictions." if "administrator" in sensitive else "."),
                    "Verify that this role is assigned only to trusted members or bots.",
                    role_id=str(role.id),
                )

    channels = sorted(guild.channels, key=lambda c: (getattr(c, "position", 0), c.id))
    exported_channels: list[dict[str, Any]] = []
    obfuscated_count = 0
    unsynced_count = 0
    for channel in channels:
        flags_value = (int(getattr(getattr(channel, "flags", None), "value", 0))
                       | getattr(guild, "raw_channel_flags", {}).get(channel.id, 0))
        obfuscated = bool(flags_value & OBFUSCATED_FLAG)
        if obfuscated:
            obfuscated_count += 1
            # Treat hidden metadata as untrusted; do not interpret it as real permission data.
            exported_channels.append({
                "id": str(channel.id), "type": str(channel.type), "obfuscated": True,
                "category_id": str(channel.category_id) if getattr(channel, "category_id", None) else None,
            })
            add_finding(
                findings, "warning", "channel_obfuscated",
                "A channel is not fully visible to the audit bot",
                "Discord obscured channel metadata; this channel cannot be fully audited.",
                "Verify the bot can view this channel and rerun the audit.",
                channel_id=str(channel.id),
            )
            continue

        category = getattr(channel, "category", None)
        sync_state = bool(channel.permissions_synced) if category is not None else None
        raw_channel_data = getattr(guild, "raw_channel_overwrites", {})
        if category is not None and channel.id in raw_channel_data and category.id in raw_channel_data:
            sync_state = raw_channel_data[channel.id] == raw_channel_data[category.id]
        if sync_state is False:
            unsynced_count += 1
        everyone_effective = one_role_permissions(channel, default_role)
        raw_overwrites: list[dict[str, Any]] = []
        member_overrides = 0
        for target, overwrite in sorted(channel.overwrites.items(), key=lambda pair: pair[0].id):
            allowed, denied = overwrite.pair()
            if isinstance(target, discord.Role) or (
                isinstance(target, discord.Object) and getattr(target, "type", None) is discord.Role
            ):
                kind = "role"
                identifier = str(target.id)
                display_name = guild.get_role(target.id).name if guild.get_role(target.id) else "Unknown role"
            else:
                kind = "member"
                member_overrides += 1
                if target.id not in member_aliases:
                    member_aliases[target.id] = f"member_{len(member_aliases) + 1}"
                identifier = member_aliases[target.id]
                display_name = identifier
            raw_entry = raw_channel_data.get(channel.id, {}).get(f"{kind}:{target.id}")
            if raw_entry is not None:
                allowed, denied = discord.Permissions(int(raw_entry["allow"])), discord.Permissions(int(raw_entry["deny"]))
            allow_names = enabled_permissions(allowed)
            deny_names = enabled_permissions(denied)
            raw_overwrites.append({
                "target_type": kind, "target_id": identifier, "target_name": display_name,
                "allow": allow_names, "deny": deny_names,
                "allow_bitfield": str(allowed.value), "deny_bitfield": str(denied.value),
            })
            if "view_channel" in deny_names and any(x in allow_names for x in ("send_messages", "connect", "speak")):
                add_finding(
                    findings, "info", "conflicting_overwrite",
                    f"Conflicting override in #{channel.name}",
                    f"{display_name}: view_channel is denied while sending or connecting is allowed.",
                    "Check whether this combination is intentional; additional roles may change effective access.",
                    channel_id=str(channel.id), target=identifier,
                )
        matrix = [
            {"role_id": str(role.id), "role_name": role.name,
             "permissions": one_role_permissions(channel, role)}
            for role in roles
        ]
        exported_channels.append({
            "id": str(channel.id), "name": channel.name, "type": str(channel.type),
            "position": getattr(channel, "position", None),
            "category_id": str(category.id) if category else None,
            "category_name": category.name if category else None,
            "permissions_synced": sync_state, "obfuscated": False,
            "everyone_effective_permissions": everyone_effective,
            "permission_overwrites": raw_overwrites,
            "member_override_count": member_overrides,
            "single_role_permission_matrix": matrix,
        })
        if SENSITIVE_NAME_RE.search(channel.name) or (category and SENSITIVE_NAME_RE.search(category.name)):
            if everyone_effective["view_channel"]:
                add_finding(
                    findings, "warning", "sensitive_channel_visible_to_everyone",
                    f"Potentially sensitive channel visible to @everyone: #{channel.name}",
                    "Name or category suggests an internal area, but @everyone can view it.",
                    "If private, deny View Channel to @everyone and review the permissions of all roles.",
                    channel_id=str(channel.id),
                )
        exposed = [p for p in SENSITIVE_CHANNEL_PERMISSIONS if everyone_effective[p]]
        if exposed and everyone_effective["view_channel"]:
            add_finding(
                findings, "critical" if "manage_roles" in exposed or "manage_webhooks" in exposed else "warning",
                "everyone_channel_moderation",
                f"@everyone has management permissions in #{channel.name}",
                "Effective permissions (@everyone only): " + ", ".join(exposed),
                "Remove @everyone management permissions unless they are explicitly required.",
                channel_id=str(channel.id),
            )
        if member_overrides:
            add_finding(
                findings, "info", "individual_member_overrides",
                f"Member-specific overwrites in #{channel.name}",
                f"{member_overrides} member(s) have channel overwrites. Member IDs were pseudonymized.",
                "Review whether these exceptions are still necessary.",
                channel_id=str(channel.id),
            )
    if unsynced_count:
        add_finding(
            findings, "info", "unsynced_channels",
            f"{unsynced_count} channel(s) are not synchronized with their category",
            "Differences may be intentional. Future category permission changes may not affect these channels.",
            "Review JSON channels with permissions_synced: false. Do not erase intended exceptions.",
        )

    bot_info: dict[str, Any] = {}
    member = guild.me
    if member:
        bot_info = {
            "role_names": [r.name for r in member.roles if not r.is_default()],
            "has_administrator": member.guild_permissions.administrator,
        }
        if member.guild_permissions.administrator:
            add_finding(
                findings, "warning", "audit_bot_admin",
                "Audit bot has Administrator permission",
                "Auditing is read-only, but compromised bot credentials could misuse this role.",
                "Remove extra bot permissions or remove the bot after auditing.",
            )
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["code"], f["title"]))
    return {
        "audit": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "bot_library": f"discord.py {discord.__version__}",
            "read_only": True, "message_content_collected": False,
            "member_names_or_ids_collected": False,
            "limitations": [
                "Single-role permissions combine @everyone plus one role, not members with multiple roles or individual overwrites.",
                "Administrator permissions bypass channel denials.",
                "Hidden or obfuscated channels cannot be fully audited.",
                "Name-based warnings are heuristics, not confirmed issues.",
                "Member-to-role assignments are not collected without Guild Members intent.",
                "Private threads and message content are not read; only cached guild channels are inspected.",
            ],
        },
        "server": {"id": str(guild.id), "name": guild.name, "role_count": len(roles),
                   "channel_count_visible_or_obfuscated": len(channels),
                   "obfuscated_channel_count": obfuscated_count,
                   "not_synced_channel_count": unsynced_count, "audit_bot": bot_info},
        "roles": exported_roles, "channels": exported_channels, "findings": findings,
        "summary": dict(Counter(f["severity"] for f in findings)),
    }


def markdown_report(data: dict[str, Any]) -> str:
    server = data["server"]
    summary = data["summary"]
    lines = [
        "# Discord Permission Audit", "",
        f"**Server:** {server['name']} (`{server['id']}`)",
        f"**Generated at (UTC):** {data['audit']['generated_at_utc']}",
        f"**Scope:** {server['role_count']} roles, {server['channel_count_visible_or_obfuscated']} channels", "",
        "## Results", "",
        f"- Critical: **{summary.get('critical', 0)}**",
        f"- Warnings: **{summary.get('warning', 0)}**",
        f"- Informational: **{summary.get('info', 0)}**",
        f"- Obfuscated channels: **{server['obfuscated_channel_count']}**", "",
        "**Important:** Findings require review and are not confirmed vulnerabilities. No changes were made.", "",
    ]
    if not data["findings"]:
        lines += ["No findings from automated checks.", ""]
    for severity in ("critical", "warning", "info"):
        subset = [f for f in data["findings"] if f["severity"] == severity]
        if not subset:
            continue
        lines += [f"## {severity.capitalize()} ({len(subset)})", ""]
        for index, item in enumerate(subset, 1):
            lines += [
                f"### {index}. {item['title']}", "",
                item["details"], "",
                f"**Recommendation:** {item['recommendation']}", "",
            ]
    lines += ["## Audit limitations", ""]
    lines.extend(f"- {limitation}" for limitation in data["audit"]["limitations"])
    lines += ["", "Review JSON exports privately and never share the bot token.", ""]
    return "\n".join(lines)


class AuditClient(discord.Client):
    def __init__(self, *, guild_id: int):
        intents = discord.Intents.none()
        intents.guilds = True  # No Guild Members / Message Content privileged intents needed.
        super().__init__(intents=intents)
        self.target_guild_id = guild_id
        self.executed = False
        self.audit_error: Exception | None = None

    async def on_ready(self) -> None:
        if self.executed:
            return
        self.executed = True
        try:
            guild = self.get_guild(self.target_guild_id)
            if guild is None:
                raise RuntimeError(
                    "Guild not found. Check GUILD_ID and make sure the bot is installed on that server."
                )
            data = prepare_snapshot(audit_guild(guild))
            paths = save_audit_bundle(data, markdown_report(data), render_html(data), OUTPUT_DIR)
            print(f"Audit completed for: {guild.name}")
            print(f"JSON:    {paths['json']}")
            print(f"Report:  {paths['markdown']}")
            print(f"HTML:    {paths['html']}")
            print(f"History: {paths['history']}")
            print(f"Results: {data['summary']}")
            if data["server"]["obfuscated_channel_count"]:
                print("WARNING: Some channels are not fully visible to the bot.")
        except Exception as exc:
            self.audit_error = exc
        finally:
            await self.close()


async def main() -> int:
    load_dotenv(BASE_DIR / ".env")
    token = os.getenv("DISCORD_TOKEN", "").strip()
    guild_id_text = os.getenv("GUILD_ID", "").strip()
    if not token:
        print("ERROR: DISCORD_TOKEN is missing from local .env.", file=sys.stderr)
        return 2
    if not guild_id_text.isdecimal():
        print("ERROR: GUILD_ID must be a numeric Discord server ID.", file=sys.stderr)
        return 2

    client = AuditClient(guild_id=int(guild_id_text))
    try:
        async with client:
            await client.start(token, reconnect=False)
    except discord.LoginFailure:
        print("ERROR: Invalid bot token. Rotate the token in Discord Developer Portal.", file=sys.stderr)
        return 1
    except discord.DiscordException as exc:
        print(f"ERROR: Discord connection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if client.audit_error:
        print(f"ERROR during audit: {client.audit_error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        sys.exit(130)
