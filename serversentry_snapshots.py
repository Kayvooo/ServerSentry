"""Versioned, private local snapshots. Standard library only; no Discord access."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = 1
TOOL_VERSION = "m2-dev"
RULESET_VERSION = "1"
RULE_CODES = (
    "everyone_global_elevated", "elevated_role_review", "channel_obfuscated",
    "conflicting_overwrite", "sensitive_channel_visible_to_everyone",
    "everyone_channel_moderation", "individual_member_overrides",
    "unsynced_channels", "audit_bot_admin",
)


def validate_snapshot(data: Any) -> dict:
    """Accept current and original (unversioned) exports without inventing coverage."""
    if not isinstance(data, dict):
        raise ValueError("Snapshot must be a JSON object")
    audit, server = data.get("audit"), data.get("server")
    if not isinstance(audit, dict) or not isinstance(server, dict):
        raise ValueError("Snapshot needs audit and server objects")
    version = audit.get("schema_version", 0)
    if type(version) is not int or version not in (0, SCHEMA_VERSION):
        raise ValueError(f"Unsupported snapshot schema: {version!r}; supported: legacy and 1")
    if not isinstance(server.get("id"), str) or not server["id"].isdecimal():
        raise ValueError("Snapshot server.id must be a numeric string")
    if not isinstance(server.get("name"), str):
        raise ValueError("Snapshot server.name must be a string")
    if not isinstance(audit.get("generated_at_utc"), str):
        raise ValueError("Snapshot needs audit.generated_at_utc")
    if not isinstance(audit.get("limitations", []), list) or any(
        not isinstance(x, str) for x in audit.get("limitations", [])
    ):
        raise ValueError("Snapshot limitations must be strings")
    if "rules_checked" in audit and (
        not isinstance(audit["rules_checked"], list)
        or any(not isinstance(x, str) for x in audit["rules_checked"])
    ):
        raise ValueError("Snapshot rules_checked must be a list of rule codes")
    if version == SCHEMA_VERSION:
        for field in ("scan_id", "tool_version", "ruleset_version"):
            if not isinstance(audit.get(field), str) or not audit[field]:
                raise ValueError(f"Version 1 snapshot needs audit.{field}")
        if "rules_checked" not in audit:
            raise ValueError("Version 1 snapshot needs audit.rules_checked")
    for collection in ("roles", "channels", "findings"):
        items = data.get(collection)
        if not isinstance(items, list) or any(not isinstance(x, dict) for x in items):
            raise ValueError(f"Snapshot {collection} must be an array of objects")
        if collection != "findings":
            ids = [x.get("id") for x in items]
            if any(not isinstance(x, str) or not x.isdecimal() for x in ids):
                raise ValueError(f"Snapshot {collection} IDs must be numeric strings")
            if len(ids) != len(set(ids)):
                raise ValueError(f"Snapshot has duplicate {collection} IDs")
            for item in items:
                if "name" in item and not isinstance(item["name"], str):
                    raise ValueError(f"Snapshot {collection} names must be strings")
    for channel in data["channels"]:
        if version == SCHEMA_VERSION:
            required = ("obfuscated",) if channel.get("obfuscated") else (
                "obfuscated", "name", "permission_overwrites", "single_role_permission_matrix",
                "everyone_effective_permissions", "member_override_count",
            )
            if any(field not in channel for field in required):
                raise ValueError("Version 1 channel is missing coverage or permission data")
        if "obfuscated" in channel and type(channel["obfuscated"]) is not bool:
            raise ValueError("Channel obfuscated must be a boolean")
        for field in ("permission_overwrites", "single_role_permission_matrix"):
            if field in channel and (
                not isinstance(channel[field], list)
                or any(not isinstance(x, dict) for x in channel[field])
            ):
                raise ValueError(f"Channel {field} must be an array of objects")
        category = channel.get("category_id")
        if category is not None and (not isinstance(category, str) or not category.isdecimal()):
            raise ValueError("Channel category_id must be a numeric string or null")
        for field in ("everyone_effective_permissions",):
            if field in channel and (
                not isinstance(channel[field], dict)
                or any(type(v) is not bool for v in channel[field].values())
            ):
                raise ValueError(f"Channel {field} must map permission names to booleans")
        for row in channel.get("single_role_permission_matrix", []):
            if (not isinstance(row.get("role_id"), str) or not row["role_id"].isdecimal()
                    or not isinstance(row.get("permissions"), dict)
                    or any(type(v) is not bool for v in row["permissions"].values())):
                raise ValueError("Invalid single-role permission matrix row")
        targets = []
        for ow in channel.get("permission_overwrites", []):
            if ow.get("target_type") not in ("role", "member") or not isinstance(ow.get("target_id"), str):
                raise ValueError("Invalid channel overwrite target")
            targets.append((ow["target_type"], ow["target_id"]))
            if ow["target_type"] == "role" and not ow["target_id"].isdecimal():
                raise ValueError("Role overwrite target must be a numeric string")
            for field in ("allow", "deny"):
                if not isinstance(ow.get(field), list) or any(not isinstance(x, str) for x in ow[field]):
                    raise ValueError("Overwrite allow/deny must contain permission names")
        if len(targets) != len(set(targets)):
            raise ValueError("Duplicate channel overwrite targets")
    for role in data["roles"]:
        if version == SCHEMA_VERSION and any(field not in role for field in ("name", "position", "guild_permissions")):
            raise ValueError("Version 1 role is missing name, position or permissions")
        if "guild_permissions" in role and (
            not isinstance(role["guild_permissions"], list)
            or any(not isinstance(x, str) for x in role["guild_permissions"])
        ):
            raise ValueError("Role guild_permissions must be permission names")
    for finding in data["findings"]:
        if finding.get("severity") not in ("critical", "warning", "info"):
            raise ValueError("Finding severity must be critical, warning or info")
        for field in ("code", "title", "details", "recommendation"):
            if not isinstance(finding.get(field), str):
                raise ValueError(f"Finding needs a string {field}")
        for field in ("role_id", "channel_id", "target"):
            if field in finding and not isinstance(finding[field], str):
                raise ValueError(f"Finding {field} must be a string")
    return data


def prepare_snapshot(data: dict) -> dict:
    result = deepcopy(validate_snapshot(data))
    result["audit"].update(
        schema_version=SCHEMA_VERSION, tool_version=TOOL_VERSION,
        scan_id=uuid4().hex, ruleset_version=RULESET_VERSION,
        rules_checked=list(RULE_CODES), channel_inventory="cached_guild_channels",
    )
    return result


def load_snapshot(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read snapshot {path}: {exc}") from exc
    return validate_snapshot(data)


def fsync_directory(path: Path) -> None:
    """Persist directory entries on POSIX; Windows has no equivalent portable API."""
    if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_write(path: Path, text: str) -> None:
    """Replace one file atomically; existing data survives failed writes/replaces."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".sentry-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        fsync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_audit_bundle(data: dict, markdown: str, html: str, output: Path) -> dict[str, Path]:
    """Keep a complete immutable run before updating individually atomic latest files."""
    validate_snapshot(data)
    scan_id = data["audit"].get("scan_id", "")
    if len(scan_id) != 32 or any(c not in "0123456789abcdef" for c in scan_id):
        raise ValueError("Prepare a versioned snapshot before saving")
    guild_id = data["server"]["id"]
    history = output / "history" / guild_id
    history.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        for directory in (output, output / "history", history):
            directory.chmod(0o700)
    run = history / scan_id
    run.mkdir(mode=0o700)  # Exclusive: never overwrite a historical run.
    payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    try:
        atomic_write(run / "report.md", markdown)
        atomic_write(run / "report.html", html)
        atomic_write(run / "snapshot.json", payload)  # Complete-run marker, written last.
    except Exception:
        shutil.rmtree(run)
        raise
    latest = {
        "json": output / f"server_audit_{guild_id}.json",
        "markdown": output / f"server_report_{guild_id}.md",
        "html": output / f"server_report_{guild_id}.html",
    }
    # These aliases are atomic per file, not a transaction; history is authoritative.
    for kind, content in (("markdown", markdown), ("html", html), ("json", payload)):
        atomic_write(latest[kind], content)
    return {**latest, "history": run}
