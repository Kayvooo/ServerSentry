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
                                default_role=role, me=None)
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
            self.assertEqual(snapshot["findings"], [])
