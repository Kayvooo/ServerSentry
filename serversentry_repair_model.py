"""Fresh Discord views and sequential, read-only repair planning."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import discord
from discord.channel import _guild_channel_factory

ACTION_TYPES = {"role_permissions", "channel_role_permissions", "mute_role_visibility",
                "cleanup_member_overrides", "sync_channel", "move_role_below", "delete_channel"}
PRIVILEGED = {"administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks",
              "ban_members", "kick_members", "moderate_members"}
OBFUSCATED = 1 << 17


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def snowflake(value: Any, label: str) -> int:
    raw = str(value)
    if type(value) not in (str, int) or not raw.isdecimal() or not 15 <= len(raw) <= 21:
        raise ValueError(f"{label} must be a numeric Discord snowflake ID, not a placeholder")
    return int(raw)


def validate_policy(data: Any) -> dict:
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("Policy must be an object with version: 1")
    if not isinstance(data.get("actions"), list):
        raise ValueError("Policy must have an actions array")
    if "guild_id" in data:
        snowflake(data["guild_id"], "guild_id")
    if not isinstance(data.get("protected_role_ids", []), list):
        raise ValueError("protected_role_ids must be an array")
    for rid in data.get("protected_role_ids", []):
        snowflake(rid, "protected_role_id")
    needed = {
        "role_permissions": ("role_id",), "channel_role_permissions": ("channel_id", "role_id"),
        "mute_role_visibility": ("role_id",), "cleanup_member_overrides": ("user_id",),
        "sync_channel": ("channel_id",), "move_role_below": ("role_id", "anchor_role_id"),
        "delete_channel": ("channel_id", "confirm_name"),
    }
    for index, action in enumerate(data["actions"], 1):
        if not isinstance(action, dict) or not isinstance(action.get("type"), str) or action["type"] not in ACTION_TYPES:
            raise ValueError(f"Unknown action at index {index}")
        kind = action["type"]
        for key in needed[kind]:
            if key not in action:
                raise ValueError(f"Action {index}: missing {key}")
            if key.endswith("_id"):
                snowflake(action[key], key)
        for key in ("allow_admin_role_edit", "allow_privilege_grant", "allow_managed_role_override",
                    "allow_overwrite_loss", "allow_delete", "remove_if_empty"):
            if key in action and type(action[key]) is not bool:
                raise ValueError(f"Action {index}: {key} must be a boolean")
        if "reason" in action and not isinstance(action["reason"], str):
            raise ValueError(f"Action {index}: reason must be a string")
        if kind == "role_permissions":
            grant, revoke = action.get("grant", []), action.get("revoke", [])
            if (not isinstance(grant, list) or not isinstance(revoke, list) or not (grant or revoke)
                    or any(not isinstance(x, str) for x in grant + revoke)):
                raise ValueError(f"Action {index}: grant/revoke need permission-name arrays")
            for flag in grant + revoke:
                if flag not in discord.Permissions.VALID_FLAGS:
                    raise ValueError(f"Invalid guild permission: {flag}")
            if _mask(grant) & _mask(revoke):
                raise ValueError(f"Action {index}: conflicting grant and revoke (including aliases)")
            if "administrator" in grant:
                raise ValueError("Granting Administrator is deliberately unsupported")
        if kind == "channel_role_permissions":
            edits = action.get("set")
            if not isinstance(edits, dict) or not edits:
                raise ValueError(f"Action {index}: set must be a nonempty object")
            for flag, value in edits.items():
                if flag not in discord.PermissionOverwrite.VALID_NAMES or (value is not None and type(value) is not bool):
                    raise ValueError(f"Invalid channel overwrite {flag}={value!r}")
            by_bit = {}
            for flag, value in edits.items():
                bit = discord.Permissions.VALID_FLAGS[flag]
                if bit in by_bit and by_bit[bit] is not value:
                    raise ValueError("Conflicting overwrite aliases")
                by_bit[bit] = value
            if edits.get("administrator") is True:
                raise ValueError("Granting Administrator is deliberately unsupported")
        if kind == "delete_channel" and (not isinstance(action["confirm_name"], str) or not action["confirm_name"]):
            raise ValueError("delete_channel needs exact confirm_name")
        if "expected_current" in action and (not isinstance(action["expected_current"], dict)
                                              or set(action["expected_current"]) != {"value"}):
            raise ValueError("expected_current must be a restore guard object with a value")
    return data


def load_policy(path: Path) -> dict:
    return validate_policy(json.loads(path.read_text(encoding="utf-8-sig")))


class FreshGuild:
    """REST results rebound to one local inventory, without updating gateway guild caches."""
    def __init__(self, raw, roles, channels, members, bot_id, channel_flags, channel_overwrites):
        self.raw = raw
        self.roles = sorted(roles)
        self.channels = list(channels)
        self._role_map = {r.id: r for r in roles}
        self._channel_map = {c.id: c for c in channels}
        self._member_map = {m.id: m for m in members}
        self.me = self._member_map[bot_id]
        self.raw_channel_flags = channel_flags
        self.raw_channel_overwrites = channel_overwrites
        for obj in [*roles, *channels, *members]:
            obj.guild = self

    def __getattr__(self, name):
        return getattr(self.raw, name)

    @property
    def default_role(self):
        return self.get_role(self.id)

    def get_role(self, rid):
        return self._role_map.get(rid)

    def get_channel(self, cid):
        return self._channel_map.get(cid)

    def get_member(self, mid):
        return self._member_map.get(mid)

    async def fetch_member(self, mid):
        member = await self.raw.fetch_member(mid)
        member.guild = self
        return member


async def fresh_guild(client, guild_id: int, member_ids=()) -> FreshGuild:
    raw = await client.fetch_guild(guild_id)
    ids = sorted({int(client.user.id), *(int(x) for x in member_ids)})
    roles, channel_data, *members = await asyncio.gather(
        raw.fetch_roles(), client.http.get_all_guild_channels(guild_id), *(raw.fetch_member(mid) for mid in ids)
    )
    # discord.py's fetch_channels drops flags for several guild-channel classes.
    # Use the same conversion factory while retaining the raw REST coverage flags.
    channels, flags, overwrites = [], {}, {}
    for entry in channel_data:
        factory, _ = _guild_channel_factory(entry["type"])
        if factory is None:
            raise ValueError("Unknown REST channel type; cannot safely plan repairs")
        payload = dict(entry)
        flags[int(entry["id"])] = int(entry.get("flags", 0))
        targets = [(ow["type"], str(ow["id"])) for ow in entry.get("permission_overwrites", [])]
        if any(kind not in (0, 1) for kind, _ in targets) or len(targets) != len(set(targets)):
            raise ValueError("Unknown or duplicate REST overwrite target; cannot safely plan repairs")
        overwrites[int(entry["id"])] = {
            f"{'role' if int(ow['type']) == 0 else 'member'}:{ow['id']}": {
                "kind": "role" if int(ow["type"]) == 0 else "member", "id": str(ow["id"]),
                "allow": str(int(ow.get("allow", 0))), "deny": str(int(ow.get("deny", 0))),
            } for ow in entry.get("permission_overwrites", [])
        }
        if flags[int(entry["id"])] & OBFUSCATED:
            payload["name"] = payload.get("name") or "Hidden channel"
            payload.setdefault("position", 0)
        channels.append(factory(guild=raw, state=raw._state, data=payload))
    return FreshGuild(raw, roles, channels, members, client.user.id, flags, overwrites)


def target_kind(target) -> str:
    return "role" if isinstance(target, discord.Role) or getattr(target, "type", None) is discord.Role else "member"


def role_overwrite_snapshot(channel) -> dict:
    raw = getattr(channel.guild, "raw_channel_overwrites", {})
    if channel.id in raw:
        return deepcopy(raw[channel.id])
    return {f"{target_kind(target)}:{target.id}": {
        "kind": target_kind(target), "id": str(target.id),
        "allow": str(overwrite.pair()[0].value), "deny": str(overwrite.pair()[1].value),
    } for target, overwrite in channel.overwrites.items()}


def guild_state(guild) -> dict:
    if guild.me is None:
        raise ValueError("Cannot inspect the bot's current member and roles")
    roles = {str(r.id): {"id": str(r.id), "name": r.name, "position": r.position,
                        "managed": r.managed, "is_default": r.id == guild.id,
                        "permissions": str(r.permissions.value)} for r in guild.roles}
    channels = {str(c.id): {
        "id": str(c.id), "name": c.name, "type": str(c.type),
        "category_id": str(c.category_id) if c.category_id else None,
        "obfuscated": bool((getattr(guild, "raw_channel_flags", {}).get(c.id, 0)
                            | int(getattr(getattr(c, "flags", None), "value", 0))) & OBFUSCATED),
        "overwrites": role_overwrite_snapshot(c),
    } for c in guild.channels}
    return {"guild_id": str(guild.id), "guild_name": guild.name, "owner_id": str(guild.owner_id),
            "roles": roles, "channels": channels,
            "bot": {"id": str(guild.me.id), "role_ids": sorted(str(r.id) for r in guild.me.roles)},
            # discord.py stores these IDs on the REST-created Guild; public channel
            # properties would resolve through its intentionally empty channel cache.
            "community_channel_ids": sorted(str(x) for x in (
                getattr(guild, "_rules_channel_id", None), getattr(guild, "_public_updates_channel_id", None),
                getattr(guild, "_safety_alerts_channel_id", None)) if x)}


def _rank(role: dict) -> tuple:
    return (-1, 0) if role.get("is_default") else (role["position"], -int(role["id"]))


def bot_permissions(state: dict, channel_id: str | None = None) -> discord.Permissions:
    roles = state["roles"]
    value = 0
    for rid in state["bot"]["role_ids"]:
        if rid not in roles:
            raise ValueError("Bot membership references an unavailable role")
        value |= int(roles[rid]["permissions"])
    if state["bot"]["id"] == state["owner_id"] or value & discord.Permissions(administrator=True).value:
        return discord.Permissions.all()
    if channel_id:
        overwrites = state["channels"][channel_id]["overwrites"]
        everyone = overwrites.get("role:" + state["guild_id"], {})
        value = (value & ~int(everyone.get("deny", 0))) | int(everyone.get("allow", 0))
        allow = deny = 0
        for rid in state["bot"]["role_ids"]:
            if rid == state["guild_id"]:
                continue
            ow = overwrites.get("role:" + rid, {})
            allow |= int(ow.get("allow", 0)); deny |= int(ow.get("deny", 0))
        value = (value & ~deny) | allow
        member = overwrites.get("member:" + state["bot"]["id"], {})
        value = (value & ~int(member.get("deny", 0))) | int(member.get("allow", 0))
    return discord.Permissions(value)


def _role(state: dict, rid, protected: set[str], *, guild_edit=False) -> dict:
    identifier = str(rid)
    role = state["roles"].get(identifier)
    if role is None or identifier == state["guild_id"] or identifier in protected:
        raise ValueError(f"Role {identifier} is missing, @everyone or protected")
    if guild_edit:
        top = max((state["roles"][x] for x in state["bot"]["role_ids"]), key=_rank)
        if role["managed"] or _rank(role) >= _rank(top):
            raise ValueError(f"Role {role['name']} is managed or at/above the bot's highest role")
    return role


def _channel(state: dict, cid) -> dict:
    channel = state["channels"].get(str(cid))
    if channel is None or channel["obfuscated"]:
        raise ValueError(f"Channel {cid} is missing or not fully inspectable")
    return channel


def _require(state: dict, names: tuple, cid: str | None = None) -> None:
    perms = bot_permissions(state, cid)
    if cid and not perms.view_channel:
        raise ValueError(f"Bot cannot view channel {cid}; cannot review this repair")
    missing = [name for name in names if not getattr(perms, name)]
    if missing:
        raise ValueError(f"Bot lacks {', '.join(missing)}" + (f" in channel {cid}" if cid else ""))


def _mask(flags) -> int:
    result = 0
    for flag in flags:
        result |= discord.Permissions.VALID_FLAGS[flag]
    return result


def _check_grants(action: dict, flags, options: dict) -> None:
    if _mask(flags) & _mask(PRIVILEGED) and not (options["grants"] and action.get("allow_privilege_grant") is True):
        raise ValueError("Privileged grants need allow_privilege_grant:true and --allow-privilege-grants")


def _overwrite_after(old: dict | None, action: dict) -> dict | None:
    old = old or {"allow": "0", "deny": "0"}
    allow, deny = int(old["allow"]), int(old["deny"])
    for key, value in action["set"].items():
        bit = discord.Permissions.VALID_FLAGS[key]
        allow &= ~bit
        deny &= ~bit
        if value is True: allow |= bit
        elif value is False: deny |= bit
    if action.get("remove_if_empty") and not (allow or deny):
        return None
    return {"kind": "role", "id": str(action["role_id"]), "allow": str(allow), "deny": str(deny)}


def _effects(before: dict, after: dict) -> list[dict]:
    result = []
    for collection in ("roles", "channels"):
        for identifier in sorted(before[collection].keys() | after[collection].keys()):
            left, right = before[collection].get(identifier), after[collection].get(identifier)
            if left != right:
                result.append({"kind": collection[:-1], "id": identifier, "before": deepcopy(left), "after": deepcopy(right)})
    return result


def _propagate_category(state: dict, cid: str, old_overwrites: dict) -> None:
    for channel in state["channels"].values():
        if channel["category_id"] == cid and channel["overwrites"] == old_overwrites:
            if channel["obfuscated"]:
                raise ValueError("Category change affects an uninspectable synced channel")
            channel["overwrites"] = deepcopy(state["channels"][cid]["overwrites"])


def _primitive(state: dict, action: dict, operation: str, options: dict, protected: set[str]) -> tuple[dict, str]:
    """Check and mutate a private projection, never Discord objects."""
    kind = operation
    label = kind
    if kind == "noop":
        return state, action.get("reason", "No changes needed")
    cid, rid = str(action.get("channel_id", "")), str(action.get("role_id", ""))
    expected = action.get("expected_current")
    if expected is not None:
        current = (state["roles"].get(rid) if kind == "role_permissions" else
                   state["channels"].get(cid, {}).get("overwrites", {}).get("role:" + rid))
        if current != expected.get("value"):
            raise ValueError("Restore guard differs from the recorded successful state; manual review required")
    if kind == "role_permissions":
        role = _role(state, rid, protected, guild_edit=True)
        old = discord.Permissions(int(role["permissions"]))
        if old.administrator and not action.get("allow_admin_role_edit"):
            raise ValueError("Administrator role needs explicit allow_admin_role_edit:true")
        _check_grants(action, action.get("grant", []), options)
        result = discord.Permissions(old.value)
        for flag in action.get("grant", []): setattr(result, flag, True)
        for flag in action.get("revoke", []): setattr(result, flag, False)
        if result != old:
            _require(state, ("manage_roles",))
            own = bot_permissions(state)
            newly_allowed = result.value & ~old.value
            if newly_allowed & ~own.value:
                raise ValueError("Bot cannot grant permissions it does not possess")
            role["permissions"] = str(result.value)
        label = f"Role {role['name']}: server permissions"
    elif kind in ("channel_role_permissions", "remove_member_overwrite"):
        channel = _channel(state, cid)
        previous = deepcopy(channel["overwrites"])
        if kind == "channel_role_permissions":
            role = _role(state, rid, protected)
            if role["managed"] and not action.get("allow_managed_role_override"):
                raise ValueError("Managed role override needs allow_managed_role_override:true")
            key = "role:" + rid
            old = channel["overwrites"].get(key)
            result = _overwrite_after(old, action)
            # Clearing a deny can also increase effective authority; require opt-in.
            possible_grants = [flag for flag, val in action["set"].items() if val is not False]
            _check_grants(action, possible_grants, options)
            label = f"#{channel['name']}: override for {role['name']}"
        else:
            key = "member:" + str(action["user_id"])
            old, result = channel["overwrites"].get(key), None
            label = f"#{channel['name']}: remove member overwrite {action['user_id']}"
        if old != result:
            _require(state, ("manage_roles",), cid)
            if kind == "channel_role_permissions":
                # Discord may further restrict which bits a bot can set; never bypass the API.
                base = bot_permissions(state)
                parent = channel["category_id"]
                available = base.value | (bot_permissions(state, parent).value if parent in state["channels"] else 0)
                explicitly_allowed = channel["overwrites"].get("member:" + state["bot"]["id"], {})
                explicit_manage = int(explicitly_allowed.get("allow", 0)) & discord.Permissions(manage_roles=True).value
                for bot_rid in state["bot"]["role_ids"]:
                    explicit_manage |= int(channel["overwrites"].get("role:" + bot_rid, {}).get("allow", 0)) & discord.Permissions(manage_roles=True).value
                changed_bits = (int((old or {}).get("allow", 0)) ^ int((result or {}).get("allow", 0))) | (int((old or {}).get("deny", 0)) ^ int((result or {}).get("deny", 0)))
                if changed_bits & ~available and not explicit_manage:
                    raise ValueError("Bot lacks a permission it would change in this channel overwrite")
            if result is None: channel["overwrites"].pop(key, None)
            else: channel["overwrites"][key] = result
            if channel["type"] == "category":
                _propagate_category(state, cid, previous)
    elif kind == "sync_channel":
        channel = _channel(state, cid)
        parent = _channel(state, channel["category_id"])
        if channel["overwrites"] != parent["overwrites"]:
            if not (options["destructive_sync"] and action.get("allow_overwrite_loss") is True):
                raise ValueError("Sync would erase custom overrides; needs allow_overwrite_loss and --allow-destructive-sync")
            for rid in protected:
                if channel["overwrites"].get("role:" + rid) != parent["overwrites"].get("role:" + rid):
                    raise ValueError("Sync would change a protected role's overwrite")
            _require(state, ("manage_channels", "manage_roles"), cid)
            _require(state, (), parent["id"])
            channel["overwrites"] = deepcopy(parent["overwrites"])
        label = f"Sync #{channel['name']} to {parent['name']} (replaces all overrides)"
    elif kind == "move_role_below":
        role = _role(state, rid, protected, guild_edit=True)
        anchor = state["roles"].get(str(action["anchor_role_id"]))
        if anchor is None or anchor["id"] == rid or anchor["position"] < 2 or discord.Permissions(int(role["permissions"])).administrator:
            raise ValueError("Invalid anchor or Administrator role cannot be moved")
        if _rank(role) >= _rank(anchor):
            _require(state, ("manage_roles",))
            destination = anchor["position"] - 1
            ranks = range(destination, role["position"] + 1)
            moved = [r for r in sorted(state["roles"].values(), key=_rank)
                     if r["position"] in ranks and r["id"] != rid and r["id"] != state["guild_id"]]
            moved.insert(0, role)
            for obj, position in zip(moved, ranks):
                if obj["id"] in protected and obj["position"] != position:
                    raise ValueError("Move would shift a protected role's position")
                obj["position"] = position
        label = f"Move {role['name']} below {anchor['name']}"
    elif kind == "delete_channel":
        channel = _channel(state, cid)
        if channel["name"] != action["confirm_name"] or action.get("allow_delete") is not True:
            raise ValueError("Deleting a channel needs exact confirm_name and allow_delete:true")
        if cid in state["community_channel_ids"] or any(c["category_id"] == cid for c in state["channels"].values()):
            raise ValueError("Cannot delete a required community channel or nonempty category")
        _require(state, ("manage_channels",), cid)
        del state["channels"][cid]
        label = f"PERMANENTLY delete #{channel['name']} (messages cannot be restored)"
    return state, label


def build_plan(guild, policy: dict, *, destructive_sync=False, grants=False) -> dict:
    validate_policy(policy)
    initial = guild_state(guild)
    if "guild_id" in policy and str(policy["guild_id"]) != initial["guild_id"]:
        raise ValueError("Policy belongs to a different server")
    projected = deepcopy(initial)
    protected = {str(x) for x in policy.get("protected_role_ids", [])}
    options = {"destructive_sync": bool(destructive_sync), "grants": bool(grants)}
    actions = []
    for source_index, original in enumerate(policy["actions"], 1):
        kind = original["type"]
        expanded = []
        if kind == "mute_role_visibility":
            role = _role(projected, original["role_id"], protected)
            if role["managed"] or discord.Permissions(int(role["permissions"])).administrator:
                raise ValueError("Muted role cannot be managed or Administrator")
            targets = [c for c in projected["channels"].values() if c["type"] == "category" or
                       c["category_id"] is None or c["category_id"] not in projected["channels"] or
                       c["overwrites"] != projected["channels"][c["category_id"]]["overwrites"]]
            for channel in sorted(targets, key=lambda c: (c["type"] != "category", c["id"])):
                expanded.append(({"type": "channel_role_permissions", "channel_id": channel["id"],
                                  "role_id": str(original["role_id"]), "set": {"view_channel": False},
                                  "reason": original.get("reason", "Mute visibility baseline")}, "channel_role_permissions"))
        elif kind == "cleanup_member_overrides":
            if guild.get_member(int(original["user_id"])) is None:
                raise ValueError("Fetch the target member before planning overwrite cleanup")
            for channel in sorted(projected["channels"].values(), key=lambda c: c["id"]):
                if "member:" + str(original["user_id"]) in channel["overwrites"]:
                    expanded.append(({**original, "channel_id": channel["id"]}, "remove_member_overwrite"))
        else:
            expanded.append((deepcopy(original), kind))
        if not expanded:
            expanded.append((deepcopy(original), "noop"))
        for action, operation in expanded:
            before = deepcopy(projected)
            try:
                projected, label = _primitive(projected, action, operation, options, protected)
            except ValueError as exc:
                raise ValueError(f"Action {source_index}: {exc}") from exc
            effects = _effects(before, projected)
            actions.append({"index": len(actions) + 1, "source_index": source_index, "operation": operation,
                            "source": action, "label": label, "changed": bool(effects), "effects": effects,
                            "guard_before": fingerprint(before), "guard_after": fingerprint(projected)})
    return {"version": 2, "plan_id": uuid4().hex, "created_at": now(), "guild_id": initial["guild_id"],
            "policy": deepcopy(policy), "options": options, "baseline": fingerprint(initial), "actions": actions,
            "preflight": {"status": "passed", "role_count": len(initial["roles"]),
                          "channel_count": len(initial["channels"]),
                          "hidden_channels": sum(c["obfuscated"] for c in initial["channels"].values()),
                          "bot_administrator": guild.me.guild_permissions.administrator,
                          "notes": ["Preflight is based on fresh REST reads, not an atomic Discord transaction.",
                                    "Each changed step is checked again before writing. The API remains authoritative."]}}


def check_saved_plan(plan: dict, guild, *, destructive_sync=False, grants=False) -> dict:
    if not isinstance(plan, dict) or plan.get("version") != 2 or not isinstance(plan.get("policy"), dict):
        raise ValueError("Unsupported or malformed repair plan")
    if plan.get("guild_id") != str(guild.id) or plan.get("baseline") != fingerprint(guild_state(guild)):
        raise ValueError("Plan is stale or belongs to another server; create and review a new plan")
    rebuilt = build_plan(guild, plan["policy"], destructive_sync=destructive_sync, grants=grants)
    if plan.get("actions") != rebuilt["actions"] or plan.get("options") != rebuilt["options"]:
        raise ValueError("Plan contents or privilege flags differ; create a new reviewed plan")
    return plan
