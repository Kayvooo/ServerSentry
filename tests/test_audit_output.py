"""Exercise the real audit callback with a synthetic guild; never connect to Discord."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import discord
import discord_audit
from serversentry_snapshots import load_snapshot


class AuditOutputTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_audit_callback_keeps_history_and_all_latest_formats(self):
        permissions = discord.Permissions(view_channel=True, send_messages=True)
        role = SimpleNamespace(id=100, name="@everyone", position=0, managed=False,
                               permissions=permissions, mentionable=False, hoist=False,
                               is_default=lambda: True, is_bot_managed=lambda: False)
        channel = SimpleNamespace(id=1000, name="lounge", type="text", position=0,
                                  category=None, category_id=None, overwrites={},
                                  permissions_for=lambda _: permissions)
        guild = SimpleNamespace(id=100, name="Synthetic guild", roles=[role], channels=[channel],
                                default_role=role, me=None, verification_level=discord.VerificationLevel.none,
                                mfa_level=discord.MFALevel.disabled)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "audit_output"
            with patch.object(discord_audit, "OUTPUT_DIR", output):
                for _ in range(2):
                    client = discord_audit.AuditClient(guild_id=100)
                    with patch.object(client, "get_guild", return_value=guild), patch.object(client, "close", new_callable=AsyncMock):
                        await client.on_ready()
                        self.assertIsNone(client.audit_error)
            self.assertEqual(len(list((output / "history/100").iterdir())), 2)
            snapshot = load_snapshot(output / "server_audit_100.json")
            self.assertEqual(snapshot["audit"]["schema_version"], 1)
            self.assertTrue(snapshot["audit"]["read_only"])
            self.assertTrue((output / "server_report_100.md").is_file())
            self.assertIn("Permission review", (output / "server_report_100.html").read_text(encoding="utf-8"))
            self.assertEqual(snapshot["audit"]["ruleset_version"], "2")
            self.assertIn("role_hierarchy_escalation", snapshot["audit"]["rules_checked"])
            self.assertNotIn("expectation_violated", snapshot["audit"]["rules_checked"])
            self.assertEqual(snapshot["server"]["settings"], {"verification_level": "none", "mfa_level": "disabled"})
            # Ruleset 2 runs inside the real audit: weak verification is reported, unknown settings are not guessed.
            self.assertEqual([f["code"] for f in snapshot["findings"]], ["server_verification_low"])

    def test_markdown_export_marks_accepted_and_expired_risks(self):
        from serversentry_policy import apply_policy, load_expectations
        root = Path(__file__).resolve().parents[1]
        data = apply_policy(load_snapshot(root / "examples/before.json"), load_expectations(root / "examples/expectations.json"))
        text = discord_audit.markdown_report(data)
        self.assertIn("Accepted risk until 2027-03-31", text)
        self.assertIn("Acceptance expired on 2026-10-01", text)
        self.assertIn("docs/rules.md#expectation_violated", text)
        self.assertIn("| Accepted risks (reviewed, time-limited) | 1 |", text)

    def test_conflicting_overwrite_fires_with_real_permission_names(self):
        # discord.py reports View Channel as `read_messages`; the rule must not depend on the alias.
        everyone = SimpleNamespace(id=100, name="@everyone", position=0, managed=False,
                                   permissions=discord.Permissions(view_channel=True), mentionable=False, hoist=False,
                                   is_default=lambda: True, is_bot_managed=lambda: False)
        helper = SimpleNamespace(id=200, name="Helpers", position=1, managed=False,
                                 permissions=discord.Permissions.none(), mentionable=False, hoist=False,
                                 is_default=lambda: False, is_bot_managed=lambda: False)
        target = discord.Object(id=200, type=discord.Role)
        overwrite = discord.PermissionOverwrite(view_channel=False, send_messages=True)
        channel = SimpleNamespace(id=1000, name="lounge", type="text", position=0, category=None, category_id=None,
                                  overwrites={target: overwrite}, permissions_for=lambda _: discord.Permissions(view_channel=True))
        guild = SimpleNamespace(id=100, name="Synthetic", roles=[everyone, helper], channels=[channel], default_role=everyone,
                                me=None, get_role=lambda rid: {200: helper}.get(rid))
        findings = discord_audit.audit_guild(guild)["findings"]
        self.assertIn("conflicting_overwrite", [f["code"] for f in findings])

    async def test_local_expectations_file_is_applied_and_recorded(self):
        permissions = discord.Permissions(view_channel=True)
        role = SimpleNamespace(id=100, name="@everyone", position=0, managed=False,
                               permissions=permissions, mentionable=False, hoist=False,
                               is_default=lambda: True, is_bot_managed=lambda: False)
        guild = SimpleNamespace(id=100, name="Synthetic guild", roles=[role], channels=[], default_role=role, me=None)
        policy = {"version": 1, "expectations": [
            {"id": "e", "type": "permission_allowlist", "permission": "view_channel", "role_ids": []}], "accepted_risks": []}
        with tempfile.TemporaryDirectory() as directory:
            output, expectations = Path(directory) / "audit_output", Path(directory) / "expectations.json"
            expectations.write_text(__import__("json").dumps(policy), encoding="utf-8")
            with patch.object(discord_audit, "OUTPUT_DIR", output), patch.object(discord_audit, "EXPECTATIONS_FILE", expectations):
                client = discord_audit.AuditClient(guild_id=100)
                with patch.object(client, "get_guild", return_value=guild), patch.object(client, "close", new_callable=AsyncMock):
                    await client.on_ready()
                    self.assertIsNone(client.audit_error)
            snapshot = load_snapshot(output / "server_audit_100.json")
            self.assertIn("expectation_violated", snapshot["audit"]["rules_checked"])
            self.assertEqual([f["code"] for f in snapshot["findings"]], ["expectation_violated"])
            self.assertEqual(snapshot["policy"]["expectations_evaluated"], 1)
