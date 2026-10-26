from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from serversentry import main
from serversentry_snapshots import load_snapshot
from serversentry_suggestions import candidates, interactive_suggestion, suggest_policy

ROOT = Path(__file__).resolve().parents[1]


class SuggestionTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = load_snapshot(ROOT / "examples/before.json")
        ids = {"100": "100000000000001", "200": "100000000000004"}
        self.snapshot["server"]["id"] = ids["100"]
        for role in self.snapshot["roles"]: role["id"] = ids[role["id"]]
        for finding in self.snapshot["findings"]:
            if "role_id" in finding: finding["role_id"] = ids[finding["role_id"]]

    def test_only_explicit_selected_revocations_are_generated(self):
        result = suggest_policy(self.snapshot, {2: ["manage_roles"]})
        self.assertEqual(result["guild_id"], self.snapshot["server"]["id"])
        self.assertEqual(result["actions"][0]["revoke"], ["manage_roles"])
        self.assertNotIn("grant", result["actions"][0])

    def test_protected_managed_admin_and_default_roles_never_proposed(self):
        identifier = self.snapshot["roles"][1]["id"]
        self.assertEqual(candidates(self.snapshot, [identifier])[0], [])
        for key, value in (("managed", True), ("guild_permissions", ["administrator", "manage_roles"])):
            with self.subTest(key=key):
                data = deepcopy(self.snapshot)
                data["roles"][1][key] = value
                self.assertEqual(candidates(data)[0], [])
        self.assertEqual(candidates(load_snapshot(ROOT / "examples/before.json"))[0], [])

    def test_unsupported_findings_flags_and_empty_selections_refused(self):
        for selection in ({}, {1: ["manage_roles"]}, {2: []}, {2: ["administrator"]}):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                suggest_policy(self.snapshot, selection)

    def test_interactive_choices_require_both_finding_and_permissions(self):
        answers = iter(["2", "manage_roles"])
        with redirect_stdout(io.StringIO()):
            source = interactive_suggestion(self.snapshot, ask=lambda _: next(answers))
        self.assertEqual(source["actions"][0]["revoke"], ["manage_roles"])

    def test_cli_is_offline_and_never_overwrites_input(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            source = Path(directory) / "snapshot.json"
            output = Path(directory) / "policy.suggested.json"
            source.write_text(json.dumps(self.snapshot), encoding="utf-8")
            args = ["suggest", str(source), "--output", str(output), "--select", "2", "--revoke", "manage_roles"]
            self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(output.read_text())["actions"][0]["revoke"], ["manage_roles"])
            original = source.read_bytes()
            self.assertEqual(main(["suggest", str(source), "--output", str(source), "--select", "2", "--revoke", "manage_roles"]), 2)
            self.assertEqual(source.read_bytes(), original)
