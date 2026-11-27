"""Ruleset 2 on plain snapshot data: no Discord connection, no token."""
from copy import deepcopy
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serversentry_rules import RULE_INFO, RULES, evaluate_rules
from serversentry_snapshots import RULE_CODES, validate_snapshot

ROOT = Path(__file__).resolve().parents[1]
SERVER = "100"
BASIC = ["view_channel", "send_messages"]


def role(identifier, name, position, perms=(), managed=False):
    return {"id": identifier, "name": name, "position": position, "is_everyone": identifier == SERVER,
            "managed": managed, "bot_managed": managed, "guild_permissions": list(perms)}


def channel(identifier, name, *, kind="text", everyone=None, overwrites=(), category=None, synced=None):
    eff = {"view_channel": True}
    eff.update(everyone or {})
    return {"id": identifier, "name": name, "type": kind, "obfuscated": False, "category_id": category,
            "permissions_synced": synced, "everyone_effective_permissions": eff,
            "permission_overwrites": list(overwrites), "member_override_count": 0,
            "single_role_permission_matrix": []}


def override(target, allow=(), deny=(), kind="role"):
    return {"target_type": kind, "target_id": target, "target_name": target, "allow": list(allow), "deny": list(deny)}


def snapshot(roles=(), channels=(), settings=None):
    server = {"id": SERVER, "name": "Synthetic"}
    if settings is not None:
        server["settings"] = settings
    return {"server": server, "roles": [role(SERVER, "@everyone", 0, BASIC), *roles], "channels": list(channels)}


def codes(data):
    return [f["code"] for f in evaluate_rules(data)]


class ServerSettingTests(unittest.TestCase):
    def test_verification_levels(self):
        self.assertEqual([f["severity"] for f in evaluate_rules(snapshot(settings={"verification_level": "none"}))], ["warning"])
        self.assertEqual([f["severity"] for f in evaluate_rules(snapshot(settings={"verification_level": "low"}))], ["info"])
        for level in ("medium", "high", "highest"):
            self.assertEqual(codes(snapshot(settings={"verification_level": level})), [])

    def test_unknown_settings_are_never_guessed(self):
        self.assertEqual(codes(snapshot()), [])
        self.assertEqual(codes(snapshot(settings={})), [])

    def test_content_filter_only_when_disabled(self):
        self.assertEqual(codes(snapshot(settings={"explicit_content_filter": "disabled"})), ["server_content_filter_off"])
        self.assertEqual(codes(snapshot(settings={"explicit_content_filter": "no_role"})), [])

    def test_mfa_needs_a_human_privileged_role(self):
        settings = {"mfa_level": "disabled"}
        self.assertEqual(codes(snapshot(settings=settings)), [])
        bot = role("200", "Bot", 1, ["administrator"], managed=True)
        self.assertEqual(codes(snapshot([bot], settings=settings)), [])
        mod = role("201", "Mods", 2, ["manage_guild"])
        self.assertEqual(codes(snapshot([mod], settings=settings)), ["server_mfa_not_required"])
        self.assertEqual(codes(snapshot([mod], settings={"mfa_level": "require_2fa"})), [])


class HierarchyTests(unittest.TestCase):
    def test_manage_roles_above_administrator_is_critical(self):
        data = snapshot([role("200", "Lead", 5, ["manage_roles"]), role("201", "Admin", 3, ["administrator"])])
        [finding] = evaluate_rules(data)
        self.assertEqual((finding["code"], finding["severity"], finding["role_id"]), ("role_hierarchy_escalation", "critical", "200"))
        self.assertIn("'Admin'", finding["details"])

    def test_role_below_the_admin_cannot_assign_it(self):
        data = snapshot([role("200", "Lead", 2, ["manage_roles"]), role("201", "Admin", 3, ["administrator"])])
        self.assertEqual(codes(data), [])

    def test_no_escalation_when_lower_role_adds_nothing(self):
        data = snapshot([role("200", "Lead", 5, ["manage_roles", "manage_channels"]), role("201", "Chan", 3, ["manage_channels"])])
        self.assertEqual(codes(data), [])

    def test_gaining_a_smaller_permission_is_a_warning(self):
        data = snapshot([role("200", "Lead", 5, ["manage_roles"]), role("201", "Chan", 3, ["manage_channels"])])
        self.assertEqual([f["severity"] for f in evaluate_rules(data)], ["warning"])

    def test_managed_roles_and_administrators_are_ignored(self):
        bot = role("201", "Bot", 3, ["administrator"], managed=True)
        self.assertEqual(codes(snapshot([role("200", "Lead", 5, ["manage_roles"]), bot])), [])
        both = role("200", "Boss", 5, ["manage_roles", "administrator"])
        self.assertEqual(codes(snapshot([both, role("201", "Admin", 3, ["administrator"])])), [])


class ChannelOverrideTests(unittest.TestCase):
    def test_role_override_is_reported_with_permissions(self):
        data = snapshot([role("200", "Helpers", 1)], [channel("1", "lounge", overwrites=[override("200", ["manage_webhooks", "send_messages"])])])
        [finding] = evaluate_rules(data)
        self.assertEqual((finding["code"], finding["role_id"], finding["channel_id"], finding["permissions"]),
                         ("role_channel_management_override", "200", "1", ["manage_webhooks"]))

    def test_everyone_member_admin_and_deny_overrides_are_not_reported_here(self):
        admin = role("201", "Admin", 2, ["administrator"])
        channels = [channel("1", "a", overwrites=[override(SERVER, ["manage_roles"]), override("9", ["manage_roles"], kind="member"),
                                                  override("201", ["manage_roles"]), override("200", deny=["manage_roles"])])]
        self.assertEqual([c for c in codes(snapshot([role("200", "H", 1), admin], channels)) if c == "role_channel_management_override"], [])

    def test_synced_children_are_reported_once_at_the_category(self):
        ow = [override("200", ["manage_channels"])]
        channels = [channel("10", "Staff", kind="category", overwrites=ow),
                    channel("11", "chat", category="10", synced=True, overwrites=ow),
                    channel("12", "own", category="10", synced=False, overwrites=ow)]
        found = [f for f in evaluate_rules(snapshot([role("200", "Helpers", 1)], channels)) if f["code"] == "role_channel_management_override"]
        self.assertEqual(sorted(f["channel_id"] for f in found), ["10", "12"])

    def test_obfuscated_channels_are_skipped(self):
        hidden = {"id": "1", "obfuscated": True, "type": "text"}
        self.assertEqual(codes(snapshot([role("200", "H", 1)], [hidden])), [])


class RoleModerationTests(unittest.TestCase):
    def test_human_role_is_info_and_bot_with_ban_is_warning(self):
        data = snapshot([role("200", "Mods", 2, ["ban_members", "manage_messages"]),
                         role("201", "Robot", 1, ["ban_members"], managed=True),
                         role("202", "Greeter", 1, ["manage_nicknames"], managed=True)])
        severities = {f["role_id"]: f["severity"] for f in evaluate_rules(data)}
        self.assertEqual(severities, {"200": "info", "201": "warning", "202": "info"})

    def test_roles_already_reviewed_as_elevated_are_skipped(self):
        self.assertEqual(codes(snapshot([role("200", "Mods", 2, ["manage_roles", "ban_members"])])), [])


class EveryoneChannelTests(unittest.TestCase):
    def test_mention_everyone_override_without_global_flag(self):
        data = snapshot(channels=[channel("1", "chat", everyone={"mention_everyone": True})])
        self.assertEqual(codes(data), ["everyone_channel_mention_everyone"])
        data["roles"][0]["guild_permissions"].append("mention_everyone")  # server-wide flag is another rule
        self.assertEqual(codes(data), [])

    def test_hidden_channels_are_not_reported(self):
        data = snapshot(channels=[channel("1", "chat", everyone={"view_channel": False, "mention_everyone": True, "mute_members": True})])
        self.assertEqual(codes(data), [])

    def test_voice_moderation_and_synced_children(self):
        flags = {"mute_members": True}
        channels = [channel("10", "Voice", kind="category", everyone=flags),
                    channel("11", "room", kind="voice", everyone=flags, category="10", synced=True),
                    channel("12", "room2", kind="voice", everyone=flags, category="10", synced=False)]
        found = [f["channel_id"] for f in evaluate_rules(snapshot(channels=channels)) if f["code"] == "everyone_voice_moderation"]
        self.assertEqual(sorted(found), ["10", "12"])

    def test_announcement_posting(self):
        news = channel("1", "news", kind="news", everyone={"send_messages": True})
        text = channel("2", "text", kind="text", everyone={"send_messages": True})
        self.assertEqual(codes(snapshot(channels=[news, text])), ["announcement_open_posting"])
        read_only = channel("3", "news2", kind="news", everyone={"send_messages": False})
        self.assertEqual(codes(snapshot(channels=[read_only])), [])


class CatalogueTests(unittest.TestCase):
    def test_every_emitted_code_is_registered_and_documented(self):
        documented = set(re.findall(r"^### `(\w+)`", (ROOT / "docs/rules.md").read_text(encoding="utf-8"), re.M))
        self.assertEqual(documented, set(RULE_INFO))
        self.assertTrue(set(RULE_CODES) <= set(RULE_INFO))
        self.assertEqual(len(RULES), 5)

    def test_findings_are_valid_snapshot_findings(self):
        data = snapshot([role("200", "Lead", 5, ["manage_roles"]), role("201", "Admin", 3, ["administrator"])],
                        [channel("1", "n", kind="news", everyone={"send_messages": True, "mention_everyone": True})],
                        settings={"verification_level": "none"})
        full = deepcopy(data)
        full.update(audit={"generated_at_utc": "2026-01-01T00:00:00+00:00", "limitations": []},
                    findings=evaluate_rules(data))
        validate_snapshot(full)
        self.assertGreaterEqual(len(full["findings"]), 4)


if __name__ == "__main__":
    unittest.main()
