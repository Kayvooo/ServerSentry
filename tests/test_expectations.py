"""M4: declared expectations and time-limited accepted risks. Offline; no token."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serversentry import main
from serversentry_compare import compare_snapshots
from serversentry_policy import (CANONICAL_PERMISSIONS, KNOWN_PERMISSIONS, PERMISSION_ALIASES, apply_policy,
                                 canonical, load_expectations, validate_expectations)
from serversentry_report import render_html
from serversentry_snapshots import load_snapshot, validate_snapshot

ROOT = Path(__file__).resolve().parents[1]


def doc(expectations=(), accepted=()):
    return {"version": 1, "expectations": list(expectations), "accepted_risks": list(accepted)}


class ValidationTests(unittest.TestCase):
    def rejects(self, data, text):
        with self.assertRaisesRegex(ValueError, text):
            validate_expectations(data)

    def test_shipped_files_are_valid(self):
        for name in ("examples/expectations.json", "config/expectations.example.json"):
            load_expectations(ROOT / name)

    def test_structure_is_checked_up_front(self):
        self.rejects([], "version: 1")
        self.rejects({"version": 2}, "version: 1")
        self.rejects({"version": 1, "extra": 1}, "Unknown top-level")
        self.rejects(doc([{"id": "a", "type": "nope"}]), "type must be")
        self.rejects(doc([{"id": "a", "type": "role_must_lack", "role_id": "1", "permissions": ["x"], "oops": 1}]), "unknown")
        item = {"id": "a", "type": "role_must_lack", "role_id": "1", "permissions": ["manage_roles"]}
        self.rejects(doc([item, item]), "duplicate id")
        self.rejects(doc([dict(item, severity="fatal")]), "severity")
        self.rejects(doc([dict(item, role_id=5)]), "numeric")
        self.rejects(doc([dict(item, role_id="YOUR_ROLE_ID")]), "numeric")

    def test_permission_typos_are_caught_with_a_hint(self):
        self.rejects(doc([{"id": "a", "type": "role_must_lack", "role_id": "1", "permissions": ["manage_role"]}]), "did you mean 'manage_roles'")

    def test_settings_and_values_are_checked(self):
        self.rejects(doc([{"id": "a", "type": "server_setting_in", "setting": "nope", "allowed": ["x"]}]), "setting must be")
        self.rejects(doc([{"id": "a", "type": "server_setting_in", "setting": "mfa_level", "allowed": ["high"]}]), "allowed must list")

    def test_accepted_risks_need_reason_expiry_and_known_code(self):
        base = {"code": "unsynced_channels", "reason": "ok", "expires": "2030-01-01"}
        validate_expectations(doc(accepted=[base]))
        self.rejects(doc(accepted=[dict(base, code="made_up")]), "known rule code")
        self.rejects(doc(accepted=[dict(base, reason="  ")]), "reason is required")
        self.rejects(doc(accepted=[{k: v for k, v in base.items() if k != "expires"}]), "YYYY-MM-DD")
        self.rejects(doc(accepted=[dict(base, expires="2030-02-31")]), "valid date")
        self.rejects(doc(accepted=[dict(base, expires="soon")]), "YYYY-MM-DD")

    def test_permission_tables_match_discord_py(self):
        import discord
        flags = discord.Permissions.VALID_FLAGS
        emitted = {name for name, _ in discord.Permissions()}
        self.assertLessEqual(set(flags), KNOWN_PERMISSIONS)  # a new discord.py flag must be added to the table
        self.assertLessEqual(emitted, CANONICAL_PERMISSIONS)
        for alias, name in PERMISSION_ALIASES.items():
            self.assertEqual(flags[alias], flags[name])
            self.assertIn(name, emitted)

    def test_broken_files_fail_with_actionable_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "e.json"
            path.write_text("{oops", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Cannot read expectations"):
                load_expectations(path)
            with self.assertRaisesRegex(ValueError, "Cannot read expectations"):
                load_expectations(Path(directory) / "missing.json")


class ExpectationTests(unittest.TestCase):
    def setUp(self):
        self.before = load_snapshot(ROOT / "examples/before.json")
        self.after = load_snapshot(ROOT / "examples/after.json")

    def findings(self, snap, code="expectation_violated"):
        return [f for f in snap["findings"] if f["code"] == code]

    def test_role_must_lack(self):
        rule = {"id": "r", "type": "role_must_lack", "role_id": "200", "permissions": ["manage_roles", "ban_members"], "reason": "because"}
        [finding] = self.findings(apply_policy(self.before, doc([rule])))
        self.assertEqual((finding["role_id"], finding["target"], finding["severity"]), ("200", "expect:r", "warning"))
        self.assertIn("manage_roles", finding["details"])
        self.assertNotIn("ban_members", finding["details"])
        self.assertIn("because", finding["details"])
        ok = dict(rule, permissions=["ban_members"])
        self.assertEqual(self.findings(apply_policy(self.before, doc([ok]))), [])

    def test_discord_ui_names_match_the_canonical_names_in_snapshots(self):
        snap = deepcopy(self.before)
        snap["roles"][1]["guild_permissions"] = ["read_messages", "manage_roles"]  # as exported by discord.py
        for written in ("view_channel", "read_messages", "manage_permissions"):
            rule = {"id": "r", "type": "role_must_lack", "role_id": "200", "permissions": [written]}
            self.assertEqual(len(self.findings(apply_policy(snap, doc([rule])))), 1, written)
        allow = {"id": "a", "type": "permission_allowlist", "permission": "view_channel", "role_ids": []}
        # @everyone (hand-written example data spells it view_channel) and the helper role both match.
        self.assertEqual(sorted(f["role_id"] for f in self.findings(apply_policy(snap, doc([allow])))), ["100", "200"])
        self.assertEqual(canonical("view_channel"), "read_messages")

    def test_missing_role_is_unverifiable_not_a_pass(self):
        rule = {"id": "r", "type": "role_must_lack", "role_id": "999", "permissions": ["manage_roles"]}
        result = apply_policy(self.before, doc([rule]))
        self.assertEqual(self.findings(result), [])
        [finding] = self.findings(result, "expectation_unverifiable")
        self.assertEqual(finding["severity"], "warning")

    def test_permission_allowlist_includes_everyone_and_skips_listed_roles(self):
        rule = {"id": "m", "type": "permission_allowlist", "permission": "mention_everyone", "role_ids": []}
        found = self.findings(apply_policy(self.after, doc([rule])))
        self.assertEqual([f["role_id"] for f in found], ["100"])
        listed = dict(rule, role_ids=["100"])
        self.assertEqual(self.findings(apply_policy(self.after, doc([listed]))), [])

    def test_channel_visible_only_to_everyone_visible(self):
        rule = {"id": "c", "type": "channel_visible_only_to", "channel_id": "1001", "role_ids": ["200"], "severity": "critical"}
        [finding] = self.findings(apply_policy(self.before, doc([rule])))
        self.assertEqual((finding["severity"], finding["channel_id"], finding["role_id"]), ("critical", "1001", "100"))
        self.assertEqual(self.findings(apply_policy(self.after, doc([rule]))), [])

    def test_channel_visible_only_to_lists_other_roles_but_not_administrators(self):
        snap = deepcopy(self.after)
        snap["roles"] += [{"id": "300", "name": "Extra", "position": 2, "guild_permissions": []},
                          {"id": "301", "name": "Boss", "position": 3, "guild_permissions": ["administrator"]}]
        channel = next(c for c in snap["channels"] if c["id"] == "1001")
        channel["single_role_permission_matrix"] = [
            {"role_id": rid, "permissions": {"view_channel": True}} for rid in ("200", "300", "301")]
        rule = {"id": "c", "type": "channel_visible_only_to", "channel_id": "1001", "role_ids": ["200"]}
        found = self.findings(apply_policy(snap, doc([rule])))
        self.assertEqual([f["role_id"] for f in found], ["300"])

    def test_hidden_channel_is_unverifiable(self):
        rule = {"id": "c", "type": "channel_visible_only_to", "channel_id": "1002", "role_ids": []}
        result = apply_policy(self.after, doc([rule]))
        self.assertEqual(len(self.findings(result, "expectation_unverifiable")), 1)

    def test_server_setting(self):
        rule = {"id": "v", "type": "server_setting_in", "setting": "verification_level", "allowed": ["high", "highest"]}
        self.assertEqual(len(self.findings(apply_policy(self.after, doc([rule])), "expectation_unverifiable")), 1)
        snap = deepcopy(self.after)
        snap["server"]["settings"] = {"verification_level": "low"}
        [finding] = self.findings(apply_policy(snap, doc([rule])))
        self.assertIn("'low'", finding["title"])
        snap["server"]["settings"]["verification_level"] = "high"
        self.assertEqual(self.findings(apply_policy(snap, doc([rule]))), [])

    def test_input_is_not_mutated_and_no_policy_means_no_change(self):
        original = deepcopy(self.before)
        apply_policy(self.before, doc([{"id": "r", "type": "role_must_lack", "role_id": "200", "permissions": ["manage_roles"]}]))
        self.assertEqual(self.before, original)
        self.assertIs(apply_policy(self.before, None), self.before)

    def test_rules_checked_only_grows_when_expectations_ran(self):
        plain = apply_policy(self.before, doc(accepted=[]))
        self.assertNotIn("expectation_violated", plain["audit"]["rules_checked"])
        rule = {"id": "r", "type": "role_must_lack", "role_id": "200", "permissions": ["manage_roles"]}
        ran = apply_policy(self.before, doc([rule]))
        self.assertIn("expectation_violated", ran["audit"]["rules_checked"])
        validate_snapshot(ran)


class AcceptedRiskTests(unittest.TestCase):
    def setUp(self):
        self.snap = load_snapshot(ROOT / "examples/before.json")  # scanned 2026-10-20

    def accept(self, **entry):
        base = {"code": "individual_member_overrides", "channel_id": "1000", "reason": "tickets", "expires": "2027-01-01"}
        return apply_policy(self.snap, doc(accepted=[{**base, **entry}]))

    def test_active_acceptance_marks_but_keeps_the_finding(self):
        result = self.accept()
        marked = [f for f in result["findings"] if "accepted" in f]
        self.assertEqual([f["code"] for f in marked], ["individual_member_overrides"])
        self.assertEqual(len(result["findings"]), len(self.snap["findings"]))
        self.assertEqual(result["policy"]["accepted_count"], 1)
        # The summary counts open findings only.
        self.assertEqual(sum(result["summary"].values()), len(self.snap["findings"]) - 1)

    def test_expiry_is_judged_on_the_scan_date(self):
        on_scan_day = self.accept(expires="2026-10-20")
        self.assertEqual(on_scan_day["policy"]["accepted_count"], 1)
        day_after = self.accept(expires="2026-10-19")
        self.assertEqual(day_after["policy"]["accepted_count"], 0)
        [expired] = [f for f in day_after["findings"] if "acceptance_expired" in f]
        self.assertEqual(expired["code"], "individual_member_overrides")
        self.assertEqual(day_after["policy"]["expired"][0]["expires"], "2026-10-19")
        self.assertEqual(sum(day_after["summary"].values()), len(self.snap["findings"]))

    def test_matching_needs_every_listed_field(self):
        self.assertEqual(self.accept(channel_id="1001")["policy"]["accepted_count"], 0)
        self.assertEqual(self.accept(channel_id="1001")["policy"]["unused_acceptances"][0]["channel_id"], "1001")
        self.assertEqual(self.accept(code="conflicting_overwrite", channel_id="1000")["policy"]["accepted_count"], 1)

    def test_expiring_soon_and_unused_are_listed(self):
        soon = self.accept(expires="2026-11-01")
        self.assertEqual(len(soon["policy"]["expiring_soon"]), 1)
        self.assertEqual(self.accept(expires="2028-01-01")["policy"]["expiring_soon"], [])

    def test_applying_the_same_policy_twice_changes_nothing(self):
        policy = load_expectations(ROOT / "examples/expectations.json")
        once = apply_policy(self.snap, policy)
        self.assertEqual(apply_policy(once, policy), once)
        self.assertEqual(sum(f["code"] == "expectation_violated" for f in once["findings"]), 2)

    def test_a_new_policy_replaces_old_marks_and_expectation_findings(self):
        policy = load_expectations(ROOT / "examples/expectations.json")
        once = apply_policy(self.snap, policy)
        cleared = apply_policy(once, doc())
        key = lambda f: json.dumps(f, sort_keys=True)  # apply_policy keeps findings sorted by severity
        self.assertEqual(sorted(cleared["findings"], key=key), sorted(self.snap["findings"], key=key))
        self.assertEqual(cleared["policy"]["accepted_count"], 0)

    def test_comparison_keeps_accepted_findings(self):
        policy = load_expectations(ROOT / "examples/expectations.json")
        before = apply_policy(load_snapshot(ROOT / "examples/before.json"), policy)
        after = apply_policy(load_snapshot(ROOT / "examples/after.json"), policy)
        result = compare_snapshots(before, after)
        statuses = {(f["code"], f["channel_id"], f["role_id"]): f["status"] for f in result["findings"]}
        self.assertEqual(statuses[("expectation_violated", "1001", "100")], "no_longer_detected")
        self.assertEqual(statuses[("expectation_violated", "", "200")], "persistent")
        self.assertTrue(any(x.get("accepted") for f in result["findings"] for x in f["after"]))

    def test_expectation_findings_without_coverage_are_not_called_fixed(self):
        policy = load_expectations(ROOT / "examples/expectations.json")
        before = apply_policy(load_snapshot(ROOT / "examples/before.json"), policy)
        after = load_snapshot(ROOT / "examples/after.json")  # evaluated without expectations
        result = compare_snapshots(before, after)
        self.assertEqual({f["status"] for f in result["findings"] if f["code"] == "expectation_violated"}, {"not_checked"})


class ReportAndCliTests(unittest.TestCase):
    def test_report_shows_accepted_expired_policy_and_links(self):
        policy = load_expectations(ROOT / "examples/expectations.json")
        html = render_html(apply_policy(load_snapshot(ROOT / "examples/before.json"), policy))
        for text in ("Accepted risk", "Acceptance expired", "Expectations &amp; accepted risks", "Acceptances that matched nothing",
                     'data-state="accepted"', 'data-state="expired"', "docs/rules.md#expectation_violated",
                     "github.com/Kayvooo/ServerSentry", 'rel="noopener noreferrer"'):
            self.assertIn(text, html)
        self.assertEqual(html.count("<script>"), 1)

    def test_hostile_reason_text_is_escaped(self):
        payload = '<img src=x onerror=alert(1)>'
        snap = load_snapshot(ROOT / "examples/before.json")
        entry = {"code": "individual_member_overrides", "reason": payload, "expires": "2030-01-01"}
        html = render_html(apply_policy(snap, doc(accepted=[entry])))
        self.assertNotIn(payload, html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_cli_applies_expectations_offline(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            output, compare = Path(directory) / "r.html", Path(directory) / "c.html"
            expectations = str(ROOT / "examples/expectations.json")
            before, after = str(ROOT / "examples/before.json"), str(ROOT / "examples/after.json")
            self.assertEqual(main(["report", before, "--output", str(output), "--expectations", expectations]), 0)
            self.assertIn("Declared expectations", output.read_text(encoding="utf-8"))
            self.assertEqual(main(["compare", before, after, "--output", str(compare), "--expectations", expectations]), 0)
            page = compare.read_text(encoding="utf-8")
            self.assertIn("Expectations &amp; accepted risks", page)
            self.assertIn("Acceptance expired", page)
            bad = Path(directory) / "bad.json"
            bad.write_text(json.dumps({"version": 1, "expectations": [{"id": "x", "type": "nope"}]}), encoding="utf-8")
            self.assertEqual(main(["report", before, "--output", str(output), "--expectations", str(bad)]), 2)


if __name__ == "__main__":
    unittest.main()
