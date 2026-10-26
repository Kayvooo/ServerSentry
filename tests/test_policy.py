"""Static policy and safety tests; no Discord token, network, or real IDs."""
import importlib
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
        class Channel:
            id=111
            name="channel"
            permissions_synced=False
            category=None
        ch=Channel()
        ch.category=type("Category",(),{"name":"category"})()
        class Guild:
            def get_channel(self,cid): return ch
        original = fixer.role_overwrite_snapshot
        try:
            def fake_snapshot(obj): return {"a":1} if obj is ch else {"a":2}
            fixer.role_overwrite_snapshot = fake_snapshot
            with self.assertRaisesRegex(ValueError,"Sync would erase"):
                fixer.make_plan(Guild(), {"actions":[{"type":"sync_channel","channel_id":"123456789012345"}]},
                                destructive_sync=False, grants=False)
        finally:
            fixer.role_overwrite_snapshot=original

    def test_repository_has_no_server_specific_ids_or_tokens(self):
        root = Path(__file__).resolve().parents[1]
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix not in {".py", ".md", ".json", ".yml", ".example"}:
                continue
            content = p.read_text(encoding="utf-8")
            self.assertNotRegex(content, r"\b\d{17,20}\b", p.as_posix())
            self.assertNotRegex(content, r"[A-Za-z0-9_-]{20,28}\.[A-Za-z0-9_-]{5,10}\.[A-Za-z0-9_-]{25,45}", p.as_posix())

if __name__=="__main__": unittest.main()
