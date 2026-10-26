from contextlib import redirect_stdout, redirect_stderr
import asyncio
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import discord
import discord_fix
from repair_fakes import Harness, GUILD, BOT, TOP, ROLE, OTHER, CATEGORY, CHANNEL, CUSTOM, MEMBER, permission_bits
from serversentry_repair_model import build_plan, check_saved_plan, fresh_guild, guild_state, validate_policy
from serversentry_repair_run import execute_plan, restore_policy, read_json


def policy(*actions, protected=()):
    return {"version": 1, "guild_id": str(GUILD), "protected_role_ids": list(map(str, protected)), "actions": list(actions)}


def role_action(**kwargs):
    return {"type": "role_permissions", "role_id": str(ROLE), "revoke": ["mention_everyone"], **kwargs}


def overwrite_action(cid=CHANNEL, **kwargs):
    return {"type": "channel_role_permissions", "channel_id": str(cid), "role_id": str(ROLE), "set": {"send_messages": False}, **kwargs}


class RepairTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.api = Harness()

    async def refresh(self):
        return await fresh_guild(self.api.client, GUILD, [MEMBER])

    async def plan(self, source, **options):
        return build_plan(await self.refresh(), source, **options)

    async def run_plan(self, plan, **options):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        return await execute_plan(plan, self.refresh, Path(self.temp.name), **options)

    async def test_refresh_uses_new_rest_data_and_resolves_category_and_bot(self):
        old = await self.refresh()
        self.api.role()["permissions"] = "0"
        fresh = await self.refresh()
        self.assertNotEqual(old.get_role(ROLE).permissions, fresh.get_role(ROLE).permissions)
        self.assertEqual(fresh.get_channel(CHANNEL).category.id, CATEGORY)
        self.assertTrue(fresh.get_channel(CHANNEL).permissions_synced)
        self.assertTrue(fresh.me.guild_permissions.manage_roles)

    async def test_sequential_actions_same_role_build_on_previous(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        self.assertEqual(plan["actions"][0]["guard_after"], plan["actions"][1]["guard_before"])
        self.assertEqual(self.api.writes, [])
        journal, run = await self.run_plan(plan)
        self.assertEqual(journal["status"], "completed")
        self.assertEqual([s["status"] for s in journal["steps"]], ["verified", "verified"])
        self.assertEqual(self.api.role()["permissions"], "0")
        self.assertTrue((run / "before/snapshot.json").is_file())
        self.assertTrue((run / "after/snapshot.json").is_file())
        self.assertTrue((run / "comparison.html").is_file())
        self.assertTrue((run / "backup.json").is_file())
        self.assertEqual(read_json(run / "journal.json")["status"], "completed")

    async def test_repeating_satisfied_policy_has_no_writes(self):
        source = policy(role_action())
        await self.run_plan(await self.plan(source))
        count = len(self.api.writes)
        journal, _ = await self.run_plan(await self.plan(source))
        self.assertEqual(len(self.api.writes), count)
        self.assertEqual(journal["steps"][0]["status"], "unchanged")

    async def test_preflight_checks_missing_permissions_and_role_hierarchy(self):
        self.api.role(TOP)["permissions"] = permission_bits(view_channel=True)
        with self.assertRaisesRegex(ValueError, "manage_roles"):
            await self.plan(policy(role_action()))
        self.api = Harness()
        self.api.role()["position"] = 4
        with self.assertRaisesRegex(ValueError, "highest role"):
            await self.plan(policy(role_action()))
        self.assertEqual(self.api.writes, [])

    async def test_channel_permissions_are_checked_in_channel(self):
        self.api.channel()["permission_overwrites"] = [{"id": str(TOP), "type": 0, "allow": "0", "deny": permission_bits(manage_roles=True)}]
        with self.assertRaisesRegex(ValueError, "manage_roles"):
            await self.plan(policy(overwrite_action()))

    async def test_hidden_channels_are_blocked_before_write(self):
        self.api.channel()["flags"] = 1 << 17
        with self.assertRaisesRegex(ValueError, "not fully inspectable"):
            await self.plan(policy(overwrite_action()))
        self.assertEqual(self.api.writes, [])
        from discord_audit import audit_guild
        result = audit_guild(await self.refresh())
        channel = next(c for c in result["channels"] if c["id"] == str(CHANNEL))
        self.assertTrue(channel["obfuscated"])
        self.assertNotIn("single_role_permission_matrix", channel)

    async def test_protected_managed_and_admin_roles_block(self):
        with self.assertRaisesRegex(ValueError, "protected"):
            await self.plan(policy(role_action(), protected=[ROLE]))
        self.api.role()["managed"] = True
        with self.assertRaisesRegex(ValueError, "managed"):
            await self.plan(policy(role_action()))
        self.api.role()["managed"] = False
        self.api.role()["permissions"] = permission_bits(administrator=True)
        with self.assertRaisesRegex(ValueError, "Administrator role"):
            await self.plan(policy(role_action()))

    async def test_grants_and_aliases_cannot_bypass_dual_opt_in(self):
        action = role_action(grant=["manage_permissions"])
        with self.assertRaisesRegex(ValueError, "Privileged grants"):
            await self.plan(policy(action))
        action["allow_privilege_grant"] = True
        with self.assertRaisesRegex(ValueError, "Privileged grants"):
            await self.plan(policy(action))
        await self.plan(policy(action), grants=True)
        for value in [1, "yes", [], {}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_policy(policy(overwrite_action(set={"send_messages": value})))
        with self.assertRaisesRegex(ValueError, "conflicting"):
            validate_policy(policy(role_action(grant=["view_channel"], revoke=["read_messages"])))

    async def test_privilege_grant_to_overwrite_and_clearing_deny_are_gated(self):
        for value in (True, None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Privileged grants"):
                await self.plan(policy(overwrite_action(set={"manage_permissions": value})))

    async def test_cannot_grant_permission_bot_does_not_have(self):
        with self.assertRaisesRegex(ValueError, "does not possess"):
            await self.plan(policy(role_action(grant=["ban_members"], allow_privilege_grant=True)), grants=True)

    async def test_stale_or_tampered_plan_is_rejected_before_writes(self):
        plan = await self.plan(policy(role_action()))
        changed = deepcopy(plan)
        changed["actions"][0]["changed"] = False
        with self.assertRaisesRegex(ValueError, "Plan contents"):
            check_saved_plan(changed, await self.refresh())
        self.api.role(OTHER)["name"] = "Renamed"
        with self.assertRaisesRegex(ValueError, "stale"):
            await self.run_plan(plan)
        self.assertEqual(self.api.writes, [])

    async def test_journal_in_progress_and_backup_exist_before_first_request(self):
        plan = await self.plan(policy(role_action()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def inspect_before_write():
                run = next(root.glob("run_*"))
                self.assertTrue((run / "backup.json").is_file())
                self.assertEqual(read_json(run / "journal.json")["steps"][0]["status"], "in_progress")
            self.api.before_write = inspect_before_write
            journal, _ = await execute_plan(plan, self.refresh, root)
            self.assertEqual(journal["status"], "completed")

    async def test_journal_failure_prevents_any_request(self):
        plan = await self.plan(policy(role_action()))
        from serversentry_repair_run import write_json as actual
        def fail(path, value):
            if path.name == "journal.json": raise OSError("disk full")
            actual(path, value)
        with patch("serversentry_repair_run.write_json", side_effect=fail), self.assertRaises(OSError):
            await self.run_plan(plan)
        self.assertEqual(self.api.writes, [])

    async def test_api_error_after_remote_success_remains_uncertain_and_stops(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        self.api.fail_after = TimeoutError("Synthetic lost response")
        journal, _ = await self.run_plan(plan)
        self.assertEqual(journal["status"], "stopped")
        self.assertEqual(journal["steps"][0]["status"], "failed_outcome_unknown")
        self.assertEqual(journal["steps"][1]["status"], "not_run")
        self.assertEqual(self.api.writes, ["role"])
        with self.assertRaisesRegex(ValueError, "not individually verified"):
            restore_policy(journal, [1])

    async def test_wrong_api_result_is_not_success(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        self.api.ignore_write = True
        journal, _ = await self.run_plan(plan)
        self.assertEqual(journal["status"], "stopped")
        self.assertEqual(journal["steps"][0]["status"], "verification_mismatch")
        self.assertEqual(journal["verification"]["status"], "unverified")
        self.assertEqual(len(self.api.writes), 1)

    async def test_failed_fresh_reads_after_success_never_report_verified(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        async def refresh():
            if self.api.writes: raise ConnectionError("Synthetic verification outage")
            return await self.refresh()
        with tempfile.TemporaryDirectory() as directory:
            journal, run = await execute_plan(plan, refresh, Path(directory))
            self.assertEqual(read_json(run / "journal.json")["verification"]["status"], "failed")
        self.assertEqual(journal["steps"][0]["status"], "unverified")
        self.assertEqual(journal["steps"][1]["status"], "not_run")
        self.assertEqual(len(self.api.writes), 1)

    async def test_post_write_journal_failure_stops_further_writes(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        from serversentry_repair_run import write_json as actual
        failed = False
        def fail_once(path, value):
            nonlocal failed
            if path.name == "journal.json" and self.api.writes and not failed:
                failed = True
                raise OSError("Synthetic journal failure")
            actual(path, value)
        with patch("serversentry_repair_run.write_json", side_effect=fail_once):
            journal, _ = await self.run_plan(plan)
        self.assertEqual(journal["status"], "stopped")
        self.assertEqual(journal["steps"][0]["status"], "journal_failed")
        self.assertEqual(journal["steps"][1]["status"], "not_run")
        self.assertEqual(len(self.api.writes), 1)

    async def test_interruption_keeps_unknown_in_progress_step_and_stops(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        self.api.fail_after = asyncio.CancelledError()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(asyncio.CancelledError):
                await execute_plan(plan, self.refresh, Path(directory))
            journal = read_json(next(Path(directory).glob("run_*/journal.json")))
        self.assertEqual(journal["status"], "interrupted")
        self.assertEqual(journal["steps"][0]["status"], "in_progress")
        self.assertEqual(journal["steps"][1]["status"], "not_run")
        self.assertEqual(len(self.api.writes), 1)

    async def test_final_verification_detects_later_changes_to_a_written_resource(self):
        plan = await self.plan(policy(role_action()))
        calls = 0
        async def refresh():
            nonlocal calls
            calls += 1
            if calls == 4: self.api.role()["name"] = "Changed after step verification"
            return await self.refresh()
        with tempfile.TemporaryDirectory() as directory:
            journal, _ = await execute_plan(plan, refresh, Path(directory))
        self.assertEqual(journal["status"], "verification_failed")
        self.assertEqual(journal["verification"]["status"], "unverified")

    async def test_self_lockout_is_detected_in_projected_sequence(self):
        # A lower bot role is its only source of Manage Roles.
        self.api.member_roles[BOT].append(str(ROLE))
        self.api.role(TOP)["permissions"] = permission_bits(view_channel=True)
        self.api.role()["permissions"] = permission_bits(manage_roles=True)
        with self.assertRaisesRegex(ValueError, "manage_roles"):
            await self.plan(policy(role_action(revoke=["manage_roles"]),
                                   role_action(role_id=str(OTHER), revoke=["send_messages"], grant=["attach_files"])))
        self.assertEqual(self.api.writes, [])

    async def test_permission_alias_conflicts_and_malformed_actions_are_rejected(self):
        for action in ({"type": []}, {"type": {}}, overwrite_action(set={"view_channel": True, "read_messages": False})):
            with self.subTest(action=action), self.assertRaises(ValueError):
                validate_policy(policy(action))

    async def test_external_change_between_steps_blocks_next_write(self):
        plan = await self.plan(policy(role_action(), role_action(revoke=["manage_webhooks"])))
        calls = 0
        async def refresh():
            nonlocal calls
            calls += 1
            if calls == 4: self.api.role(OTHER)["name"] = "Concurrent edit"
            return await self.refresh()
        with tempfile.TemporaryDirectory() as directory:
            journal, _ = await execute_plan(plan, refresh, Path(directory))
        self.assertEqual(journal["steps"][1]["status"], "blocked")
        self.assertEqual(len(self.api.writes), 1)

    async def test_mute_category_changes_synced_children_but_keeps_custom_overwrites(self):
        plan = await self.plan(policy({"type": "mute_role_visibility", "role_id": str(ROLE)}))
        self.assertEqual(len(plan["actions"]), 2)
        self.assertEqual(len(plan["actions"][0]["effects"]), 2)
        journal, _ = await self.run_plan(plan)
        self.assertEqual(journal["status"], "completed")
        self.assertTrue(any(x["id"] == str(OTHER) for x in self.api.channel(CUSTOM)["permission_overwrites"]))
        self.assertEqual(self.api.writes, ["overwrite", "overwrite"])

    async def test_sequential_overwrites_and_reverse_restore(self):
        original = deepcopy(self.api.channel()["permission_overwrites"])
        plan = await self.plan(policy(overwrite_action(), overwrite_action(set={"attach_files": False})))
        journal, _ = await self.run_plan(plan)
        source, notes = restore_policy(journal, [1, 2])
        self.assertEqual(len(notes), 2)
        restored, _ = await self.run_plan(await self.plan(source))
        self.assertEqual(restored["status"], "completed")
        self.assertEqual(self.api.channel()["permission_overwrites"], original)

    async def test_unknown_permission_bits_are_preserved_by_edit_and_recovery(self):
        unknown = 1 << 100
        original = {"id": str(ROLE), "type": 0, "allow": str(unknown), "deny": "0"}
        self.api.channel()["permission_overwrites"] = [original.copy()]
        journal, _ = await self.run_plan(await self.plan(policy(overwrite_action())))
        self.assertEqual(journal["status"], "completed")
        self.assertEqual(int(self.api.channel()["permission_overwrites"][0]["allow"]), unknown)
        source, _ = restore_policy(journal, [1])
        result, _ = await self.run_plan(await self.plan(source))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.api.channel()["permission_overwrites"], [original])

    async def test_raw_unknown_bits_affect_sync_state_and_audit_evidence(self):
        from discord_audit import audit_guild
        for cid, shift in ((CATEGORY, 100), (CHANNEL, 101)):
            self.api.channel(cid)["permission_overwrites"] = [{"id": str(ROLE), "type": 0, "allow": str(1 << shift), "deny": "0"}]
        guild = await self.refresh()
        audit = audit_guild(guild)
        channel = next(c for c in audit["channels"] if c["id"] == str(CHANNEL))
        self.assertFalse(channel["permissions_synced"])
        self.assertEqual(int(channel["permission_overwrites"][0]["allow_bitfield"]), 1 << 101)

    async def test_role_restore_uses_guards_and_grant_gates(self):
        original = self.api.role()["permissions"]
        journal, _ = await self.run_plan(await self.plan(policy(role_action(revoke=["manage_webhooks"]))))
        source, _ = restore_policy(journal, [1])
        with self.assertRaisesRegex(ValueError, "Privileged grants"):
            await self.plan(source)
        restore = await self.plan(source, grants=True)
        result, _ = await self.run_plan(restore, grants=True)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.api.role()["permissions"], original)

    async def test_administrator_cannot_be_restored_as_a_grant(self):
        self.api.role()["permissions"] = permission_bits(administrator=True)
        action = role_action(revoke=["administrator"], allow_admin_role_edit=True)
        journal, _ = await self.run_plan(await self.plan(policy(action)))
        with self.assertRaisesRegex(ValueError, "Administrator cannot be granted"):
            restore_policy(journal, [1])

    async def test_later_edits_make_selected_restore_refuse(self):
        journal, _ = await self.run_plan(await self.plan(policy(overwrite_action())))
        source, _ = restore_policy(journal, [1])
        self.api.channel()["permission_overwrites"][0]["deny"] = permission_bits(attach_files=True)
        with self.assertRaisesRegex(ValueError, "Restore guard"):
            await self.plan(source)

    async def test_sync_needs_both_guards_and_keeps_protected_roles(self):
        action = {"type": "sync_channel", "channel_id": str(CUSTOM)}
        with self.assertRaisesRegex(ValueError, "Sync would erase"):
            await self.plan(policy(action))
        action["allow_overwrite_loss"] = True
        with self.assertRaisesRegex(ValueError, "Sync would erase"):
            await self.plan(policy(action))
        with self.assertRaisesRegex(ValueError, "protected role"):
            await self.plan(policy(action, protected=[OTHER]), destructive_sync=True)
        plan = await self.plan(policy(action), destructive_sync=True)
        journal, _ = await self.run_plan(plan, destructive_sync=True)
        self.assertEqual(journal["status"], "completed")
        with self.assertRaisesRegex(ValueError, "cannot be restored"):
            restore_policy(journal, [1])

    async def test_move_and_delete_have_no_automatic_restore(self):
        action = {"type": "move_role_below", "role_id": str(OTHER), "anchor_role_id": str(TOP)}
        # Already below: no reordering request.
        plan = await self.plan(policy(action))
        self.assertFalse(plan["actions"][0]["changed"])
        action = {"type": "delete_channel", "channel_id": str(CUSTOM), "confirm_name": "custom", "allow_delete": True}
        journal, _ = await self.run_plan(await self.plan(policy(action)))
        self.assertEqual(journal["status"], "completed")
        with self.assertRaisesRegex(ValueError, "cannot be restored"):
            restore_policy(journal, [1])

    async def test_role_move_changed_positions_are_applied_in_one_request(self):
        self.api.role(ROLE)["position"] = 3
        self.api.role(OTHER)["position"] = 2
        self.api.role(TOP)["position"] = 4
        plan = await self.plan(policy({"type": "move_role_below", "role_id": str(ROLE), "anchor_role_id": str(OTHER)}))
        journal, _ = await self.run_plan(plan)
        self.assertEqual(journal["status"], "completed")
        self.assertLess(self.api.role(ROLE)["position"], self.api.role(OTHER)["position"])
        self.assertEqual(self.api.writes, ["positions"])

    async def test_changing_servers_or_flags_rejects_a_saved_plan(self):
        plan = await self.plan(policy(role_action()))
        with self.assertRaisesRegex(ValueError, "privilege flags"):
            check_saved_plan(plan, await self.refresh(), grants=True)
        other = deepcopy(plan)
        other["guild_id"] = str(OTHER)
        with self.assertRaisesRegex(ValueError, "another server"):
            check_saved_plan(other, await self.refresh())

    async def test_malformed_and_unsupported_restore_selections_fail_closed(self):
        for journal, selected in (({}, [1]), ({"version": 2, "guild_id": str(GUILD), "steps": [], "reviewed_plan": None}, [1]),
                                  ({"version": 2, "guild_id": str(GUILD), "steps": [None]}, [1])):
            with self.subTest(journal=journal), self.assertRaises(ValueError):
                restore_policy(journal, selected)

    async def test_required_community_channel_cannot_be_deleted(self):
        self.api.guild_extra["rules_channel_id"] = str(CUSTOM)
        with self.assertRaisesRegex(ValueError, "required community"):
            await self.plan(policy({"type": "delete_channel", "channel_id": str(CUSTOM), "confirm_name": "custom", "allow_delete": True}))

    async def test_cleanup_member_is_expanded_and_does_not_touch_role_overwrites(self):
        self.api.channel(CUSTOM)["permission_overwrites"].append({"id": str(MEMBER), "type": 1, "allow": "0", "deny": permission_bits(send_messages=True)})
        journal, _ = await self.run_plan(await self.plan(policy({"type": "cleanup_member_overrides", "user_id": str(MEMBER)})))
        self.assertEqual(journal["status"], "completed")
        self.assertEqual(len(self.api.channel(CUSTOM)["permission_overwrites"]), 1)
        self.assertEqual(self.api.channel(CUSTOM)["permission_overwrites"][0]["type"], 0)

    async def test_cli_preview_and_cancel_never_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "policy.json"
            path.write_text(json.dumps(policy(role_action())), encoding="utf-8")
            async def start(*args, **kwargs): await self.api.client.on_ready()
            with patch.dict(os.environ, {"DISCORD_TOKEN": "synthetic-test-value", "GUILD_ID": str(GUILD)}), \
                 patch.object(discord_fix, "OUTPUT", root / "output"), \
                 patch("discord_fix.discord.Client", return_value=self.api.client), \
                 patch.object(self.api.client, "start", side_effect=start), \
                 patch("builtins.input", return_value="cancel"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(await discord_fix.main(["--policy", str(path), "--apply"]), 0)
            self.assertEqual(self.api.writes, [])
            self.assertEqual(len(list((root / "output").glob("plan_*.json"))), 1)

    async def test_cli_saved_plan_confirmation_executes_and_verifies(self):
        reviewed = await self.plan(policy(role_action()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "plan.json"
            path.write_text(json.dumps(reviewed), encoding="utf-8")
            async def start(*args, **kwargs): await self.api.client.on_ready()
            with patch.dict(os.environ, {"DISCORD_TOKEN": "synthetic-test-value", "GUILD_ID": str(GUILD)}), \
                 patch.object(discord_fix, "OUTPUT", root / "output"), \
                 patch("discord_fix.discord.Client", return_value=self.api.client), \
                 patch.object(self.api.client, "start", side_effect=start), \
                 patch("builtins.input", return_value=f"APPLY {GUILD}"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(await discord_fix.main(["--plan", str(path), "--apply"]), 0)
            result = read_json(next((root / "output").glob("run_*/journal.json")))
            self.assertEqual(result["status"], "completed")
            self.assertEqual(self.api.writes, ["role"])
