"""Static policy and safety tests; no Discord token, network, or real IDs."""
import importlib
import asyncio
from pathlib import Path
import sys
import unittest

# Run policy tests against the actual supported discord.py dependency.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
fixer = importlib.import_module("discord_fix")


class PolicySafetyTests(unittest.TestCase):
    def test_empty_policy(self):
        self.assertEqual(fixer.validate_policy({"version":1, "actions":[]}), {"version":1, "actions":[]})

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            fixer.validate_policy({"version":1,"actions":[{"type":"wipe_everything"}]})

    def test_placeholder_rejected(self):
        with self.assertRaises(ValueError):
            fixer.validate_policy({"version":1,"actions":[{"type":"cleanup_member_overrides","user_id":"USER_ID"}]})

    def test_admin_grants_rejected(self):
        with self.assertRaises(ValueError):
            fixer.validate_policy({"version":1,"actions":[{"type":"role_permissions", "role_id":"123456789012345", "grant":["administrator"]}]})

    def test_conflicting_role_flags_rejected(self):
        with self.assertRaises(ValueError):
            fixer.validate_policy({"version":1,"actions":[{"type":"role_permissions", "role_id":"123456789012345", "grant":["mention_everyone"], "revoke":["mention_everyone"]}]})

    def test_revoke_role_permission_accepted(self):
        self.assertEqual(len(fixer.validate_policy({"version":1,"protected_role_ids":["123456789012345"],
            "actions":[{"type":"role_permissions", "role_id":"123456789012346", "revoke":["mention_everyone"]}]})["actions"]),1)

    def test_sync_difference_fails_closed(self):
        from repair_fakes import Harness, GUILD, CUSTOM
        from serversentry_repair_model import fresh_guild
        async def scenario():
            api = Harness()
            guild = await fresh_guild(api.client, GUILD)
            fixer.make_plan(guild, {"version": 1, "actions": [{"type": "sync_channel", "channel_id": str(CUSTOM)}]})
        with self.assertRaisesRegex(ValueError, "Sync would erase"):
            asyncio.run(scenario())

    def test_repository_has_no_server_specific_ids_or_tokens(self):
        root = Path(__file__).resolve().parents[1]
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix not in {".py", ".md", ".json", ".yml", ".example"}:
                continue
            content = p.read_text(encoding="utf-8")
            self.assertNotRegex(content, r"\b\d{17,20}\b", p.as_posix())
            self.assertNotRegex(content, r"[A-Za-z0-9_-]{20,28}\.[A-Za-z0-9_-]{5,10}\.[A-Za-z0-9_-]{25,45}", p.as_posix())

if __name__=="__main__": unittest.main()
