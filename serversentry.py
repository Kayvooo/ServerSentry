#!/usr/bin/env python3
"""Offline report and comparison commands; no bot token or third-party packages."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from serversentry_compare import compare_snapshots
from serversentry_report import render_html
from serversentry_snapshots import atomic_write, load_snapshot


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="ServerSentry offline reports (no token needed)")
    commands = cli.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report", help="Render a current or legacy audit as a local HTML file")
    report.add_argument("snapshot", type=Path)
    report.add_argument("--output", type=Path, required=True, help="Destination HTML file")
    compare = commands.add_parser("compare", help="Compare two audits from the same server")
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    compare.add_argument("--output", type=Path, required=True, help="Destination HTML file")
    compare.add_argument("--json-output", type=Path, help="Optional machine-readable comparison")
    demo = commands.add_parser("demo", help="Generate a comparison from bundled synthetic examples")
    demo.add_argument("--output", type=Path, default=Path("audit_output/demo.html"))
    suggest = commands.add_parser("suggest", help="Choose supported permission revocations from an audit (offline)")
    suggest.add_argument("snapshot", type=Path)
    suggest.add_argument("--output", type=Path, required=True, help="Local suggested policy JSON; review before use")
    suggest.add_argument("--select", help="Explicit finding numbers, otherwise ask interactively")
    suggest.add_argument("--revoke", help="Explicit permission names for the selected findings, otherwise ask")
    suggest.add_argument("--protect-role", action="append", default=[], help="Additional role ID never to propose editing")
    return cli


def _protect_inputs(inputs: list[Path], outputs: list[Path]) -> None:
    normalized = [p.resolve() for p in outputs]
    if len(normalized) != len(set(normalized)):
        raise ValueError("Output paths must be different")
    sources = {p.resolve() for p in inputs}
    if any(p in sources for p in normalized):
        raise ValueError("Output must not overwrite an input snapshot")
    for path in outputs:
        if path.suffix.lower() == ".json" and path == outputs[0]:
            raise ValueError("HTML output needs an .html extension, not .json")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "suggest":
            from serversentry_suggestions import interactive_suggestion
            if args.snapshot.resolve() == args.output.resolve():
                raise ValueError("Output must not overwrite an input snapshot")
            policy = interactive_suggestion(load_snapshot(args.snapshot), selected=args.select, revoke=args.revoke,
                                            protected_ids=args.protect_role)
            atomic_write(args.output, json.dumps(policy, ensure_ascii=False, indent=2) + "\n")
            print(f"Suggested policy: {args.output}. Review it; no Discord connection or changes.")
            return 0
        if args.command == "report":
            _protect_inputs([args.snapshot], [args.output])
            html = render_html(load_snapshot(args.snapshot))
            comparison = None
        else:
            if args.command == "demo":
                examples = Path(__file__).resolve().parent / "examples"
                before_path, after_path = examples / "before.json", examples / "after.json"
                json_output = None
            else:
                before_path, after_path = args.before, args.after
                json_output = args.json_output
            outputs = [args.output] + ([json_output] if json_output else [])
            _protect_inputs([before_path, after_path], outputs)
            before, after = load_snapshot(before_path), load_snapshot(after_path)
            comparison = compare_snapshots(before, after)
            html = render_html(after, comparison, before)
            if json_output:
                atomic_write(json_output, json.dumps(comparison, ensure_ascii=False, indent=2) + "\n")
                print(f"Comparison JSON: {json_output}")
        atomic_write(args.output, html)
        print(f"Local HTML report: {args.output}")
        if comparison:
            print("Finding groups:", json.dumps(comparison["summary"], sort_keys=True))
        print("No Discord connection or changes. Reports contain private server data.")
        return 0
    except (ValueError, OSError, EOFError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
