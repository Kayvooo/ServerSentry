"""M1 regression tests; standard library only, no Discord connection or token."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serversentry import main
from serversentry_compare import compare_snapshots
from serversentry_report import render_html
from serversentry_snapshots import atomic_write, load_snapshot, prepare_snapshot, save_audit_bundle, validate_snapshot

ROOT = Path(__file__).resolve().parents[1]


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.before = load_snapshot(ROOT / "examples/before.json")
        self.after = load_snapshot(ROOT / "examples/after.json")

    def status_for(self, result, code, channel_id=""):
        return next(x["status"] for x in result["findings"] if x["code"] == code and x["channel_id"] == channel_id)

    def test_demo_expected_statuses(self):
        result = compare_snapshots(self.before, self.after)
        self.assertEqual(result["summary"], {"newly_reported": 1, "no_longer_detected": 2,
                                         "not_checked": 1, "not_comparable": 1,
                                         "persistent": 2, "severity_changed": 1})
        self.assertEqual(self.status_for(result, "sensitive_channel_visible_to_everyone", "1002"), "not_checked")

    def test_time_ids_order_and_redundant_bitfields_do_not_change_data(self):
        other = deepcopy(self.before)
        other["audit"]["generated_at_utc"] = "2026-10-22T12:00:00+00:00"
        other["audit"]["scan_id"] = "c" * 32
        other["roles"].reverse()
        other["channels"].reverse()
        other["findings"].reverse()
        for role in other["roles"]:
            role["guild_permissions"].reverse()
            role["guild_permissions_bitfield"] = "unneeded representation"
        result = compare_snapshots(self.before, other)
        self.assertEqual(result["changes"], [])
        self.assertNotIn("no_longer_detected", result["summary"])

    def test_rename_is_one_object_change_not_add_remove(self):
        other = deepcopy(self.before)
        other["roles"][1]["name"] = "Renamed helpers"
        other["findings"][1]["title"] = "Role 'Renamed helpers' has powerful permissions"
        result = compare_snapshots(self.before, other)
        self.assertEqual(len(result["changes"]), 1)
        self.assertEqual(result["changes"][0]["fields"], ["name"])
        self.assertEqual(self.status_for(result, "elevated_role_review"), "persistent")

    def test_permissions_position_and_sync_changes(self):
        other = deepcopy(self.before)
        other["roles"][1]["position"] = 9
        other["roles"][1]["guild_permissions"] = []
        other["channels"][0]["permissions_synced"] = False
        result = compare_snapshots(self.before, other)
        self.assertIn("guild_permissions", result["changes"][0]["fields"])
        self.assertIn("position", result["changes"][0]["fields"])
        self.assertIn("permissions_synced", result["changes"][1]["fields"])

    def test_member_alias_renumbering_does_not_change_channel_patterns(self):
        other = deepcopy(self.before)
        overwrite = other["channels"][0]["permission_overwrites"][0]
        overwrite["target_id"] = overwrite["target_name"] = "member_99"
        other["findings"][5]["target"] = "member_99"
        result = compare_snapshots(self.before, other)
        self.assertEqual(result["changes"], [])
        self.assertEqual(self.status_for(result, "conflicting_overwrite", "1000"), "not_comparable")

    def test_member_pattern_changes_are_only_aggregate(self):
        other = deepcopy(self.before)
        other["channels"][0]["permission_overwrites"][0]["allow"] = []
        changes = compare_snapshots(self.before, other)["changes"]
        self.assertEqual(changes[0]["fields"], ["member_overwrite_patterns_aggregate_only"])
        self.assertNotIn("member_1", json.dumps(changes))

    def test_legacy_missing_findings_are_not_fixed(self):
        for field in ("schema_version", "ruleset_version", "rules_checked", "scan_id"):
            self.before["audit"].pop(field, None)
        result = compare_snapshots(self.before, self.after)
        self.assertNotIn("no_longer_detected", result["summary"])
        self.assertIn("Legacy snapshot", " ".join(result["limitations"]))
        self.assertIn("Legacy export", render_html(self.before))

    def test_rule_changes_and_missing_rule_coverage_are_unverified(self):
        for field, value in (("ruleset_version", "2"), ("rules_checked", [])):
            with self.subTest(field=field):
                other = deepcopy(self.after)
                other["audit"][field] = value
                result = compare_snapshots(self.before, other)
                self.assertEqual(self.status_for(result, "everyone_channel_moderation", "1000"), "not_checked")

    def test_missing_channel_is_not_claimed_deleted_or_fixed(self):
        self.after["channels"] = [c for c in self.after["channels"] if c["id"] != "1001"]
        result = compare_snapshots(self.before, self.after)
        self.assertEqual(self.status_for(result, "sensitive_channel_visible_to_everyone", "1001"), "not_checked")
        change = next(c for c in result["changes"] if c["id"] == "1001")
        self.assertEqual(change["status"], "removed_or_unavailable")

    def test_removed_role_is_distinct_from_fixed(self):
        self.after["roles"] = [r for r in self.after["roles"] if r["id"] != "200"]
        self.after["findings"] = [f for f in self.after["findings"] if f.get("role_id") != "200"]
        result = compare_snapshots(self.before, self.after)
        self.assertEqual(self.status_for(result, "elevated_role_review"), "target_removed")

    def test_removed_role_overwrite_target_is_not_a_fix(self):
        self.before["findings"][5]["target"] = "200"
        self.after["roles"] = [r for r in self.after["roles"] if r["id"] != "200"]
        self.after["findings"] = [f for f in self.after["findings"] if f["code"] != "conflicting_overwrite"]
        result = compare_snapshots(self.before, self.after)
        self.assertEqual(self.status_for(result, "conflicting_overwrite", "1000"), "target_removed")

    def test_different_servers_rejected(self):
        self.after["server"]["id"] = "101"
        with self.assertRaisesRegex(ValueError, "different servers"):
            compare_snapshots(self.before, self.after)

    def test_bad_snapshots_fail_with_actionable_errors(self):
        invalid = [None, {}, {"audit": {}, "server": {}}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_snapshot(value)
        for mutate in (
            lambda s: s["audit"].update(schema_version=99),
            lambda s: s["roles"].append(deepcopy(s["roles"][0])),
            lambda s: s["channels"][0].update(permission_overwrites=[{"target_type": "member"}]),
            lambda s: s["channels"][0].update(single_role_permission_matrix=[{"role_id": {}}]),
            lambda s: s["findings"][0].update(severity="safe"),
        ):
            value = deepcopy(self.before)
            mutate(value)
            with self.assertRaises(ValueError):
                validate_snapshot(value)

    def test_html_escapes_untrusted_names_evidence_and_attributes(self):
        payload = '</title><script>globalThis.injected=true</script><img src=x onerror=alert(1)>'
        self.before["server"]["name"] = payload
        self.before["roles"][0]["name"] = payload
        self.before["findings"][0].update(title=payload, details=payload, code='test" onmouseover="bad')
        html = render_html(self.before)
        self.assertNotIn(payload, html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("test&quot; onmouseover=&quot;bad", html)
        self.assertEqual(html.count("<script>"), 1)
        self.assertIn("connect-src 'none'", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("<link ", html)

    def test_large_synthetic_report_keeps_every_finding_and_filter_target(self):
        base = self.before["findings"][0]
        self.before["findings"] = [dict(base, code=f"synthetic_rule_{index}", title=f"Scenario {index}")
                                   for index in range(1500)]
        html = render_html(self.before)
        self.assertEqual(html.count('data-severity="critical"'), 1500)
        self.assertIn('data-rule="synthetic_rule_1499"', html)

    def test_independent_historical_runs_and_compatible_latest_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            first, second = prepare_snapshot(self.before), prepare_snapshot(self.after)
            paths1 = save_audit_bundle(first, "first markdown", render_html(first), root)
            paths2 = save_audit_bundle(second, "second markdown", render_html(second), root)
            self.assertNotEqual(paths1["history"], paths2["history"])
            self.assertEqual(load_snapshot(paths1["history"] / "snapshot.json"), first)
            self.assertEqual(load_snapshot(paths2["json"]), second)
            self.assertEqual(paths2["json"].name, "server_audit_100.json")
            self.assertEqual(paths2["markdown"].read_text(), "second markdown")
            if os.name != "nt":
                self.assertEqual(paths2["json"].stat().st_mode & 0o777, 0o600)
                self.assertEqual(paths2["history"].stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                save_audit_bundle(second, "overwrite", "overwrite", root)

    def test_failed_atomic_replace_keeps_old_file_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text("original", encoding="utf-8")
            with patch("serversentry_snapshots.os.replace", side_effect=OSError("simulated disk error")):
                with self.assertRaises(OSError):
                    atomic_write(path, "replacement")
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_partial_history_is_removed_latest_remains_intact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = prepare_snapshot(self.before)
            paths = save_audit_bundle(first, "first", "html", root)
            original = paths["json"].read_bytes()
            with patch("serversentry_snapshots.atomic_write", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    save_audit_bundle(prepare_snapshot(self.after), "second", "html", root)
            self.assertEqual(paths["json"].read_bytes(), original)
            self.assertEqual(len(list((root / "history/100").iterdir())), 1)

    def test_complete_history_survives_latest_update_failure(self):
        from serversentry_snapshots import atomic_write as real_write
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def fail_latest(path, content):
                if path.name.startswith("server_"):
                    raise OSError("cannot update latest")
                real_write(path, content)
            data = prepare_snapshot(self.before)
            with patch("serversentry_snapshots.atomic_write", side_effect=fail_latest):
                with self.assertRaises(OSError):
                    save_audit_bundle(data, "report", "html", root)
            self.assertEqual(load_snapshot(root / "history/100" / data["audit"]["scan_id"] / "snapshot.json"), data)

    def test_cli_demo_report_compare_and_input_protection(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            output = Path(directory) / "report.html"
            json_output = Path(directory) / "diff.json"
            self.assertEqual(main(["demo", "--output", str(output)]), 0)
            self.assertIn("Permission changes", output.read_text())
            before, after = str(ROOT / "examples/before.json"), str(ROOT / "examples/after.json")
            self.assertEqual(main(["report", before, "--output", str(output)]), 0)
            self.assertEqual(main(["compare", before, after, "--output", str(output), "--json-output", str(json_output)]), 0)
            self.assertEqual(json.loads(json_output.read_text())["summary"]["not_checked"], 1)
            self.assertEqual(main(["report", before, "--output", before]), 2)
            self.assertEqual(main(["compare", before, after, "--output", str(output), "--json-output", str(output)]), 2)
            broken = Path(directory) / "broken.json"
            broken.write_text("not json", encoding="utf-8")
            self.assertEqual(main(["report", str(broken), "--output", str(output)]), 2)
            self.assertEqual(main(["report", str(broken.with_name("missing.json")), "--output", str(output)]), 2)


if __name__ == "__main__":
    unittest.main()
