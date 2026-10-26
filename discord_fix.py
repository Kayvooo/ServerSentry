#!/usr/bin/env python3
"""Explicit one-shot repairs: fresh preview, confirmation, journal and verification."""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import sys

import discord
from dotenv import load_dotenv

from serversentry_repair_model import (
    ACTION_TYPES, PRIVILEGED, build_plan, check_saved_plan, fresh_guild,
    guild_state, load_policy, role_overwrite_snapshot, snowflake, validate_policy,
)
from serversentry_repair_run import execute_plan, read_json, restore_policy, save_private_json

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "fixer_output"


def make_plan(guild, policy, *, destructive_sync=False, grants=False):
    """Compatibility entry point returning the primitive steps of the new plan."""
    return build_plan(guild, policy, destructive_sync=destructive_sync, grants=grants)["actions"]


def _permission_names(bits: str) -> str:
    return ", ".join(name for name, allowed in discord.Permissions(int(bits)) if allowed) or "none"


def print_plan(plan: dict) -> None:
    checks = plan["preflight"]
    print(f"PREFLIGHT PASSED: {checks['role_count']} roles, {checks['channel_count']} REST-listed channels")
    if checks["bot_administrator"]:
        print("REVIEW: bot currently has Administrator; prefer the minimum required permissions")
    if checks["hidden_channels"]:
        print(f"LIMIT: {checks['hidden_channels']} channel(s) are not fully inspectable")
    for item in plan["actions"]:
        print(f"[{'CHANGE' if item['changed'] else 'NO-OP'}] #{item['index']} (policy action {item['source_index']}): {item['label']}")
        print("  Reason:", item["source"].get("reason", "User-configured action"))
        for effect in item["effects"]:
            before, after = effect["before"], effect["after"]
            if effect["kind"] == "role":
                if before["permissions"] != after["permissions"]:
                    print(f"  {before['name']} before: {_permission_names(before['permissions'])}")
                    print(f"  {after['name']} after:  {_permission_names(after['permissions'])}")
                if before["position"] != after["position"]:
                    print(f"  {before['name']} position: {before['position']} -> {after['position']}")
            elif after is None:
                print(f"  #{before['name']}: permanently deleted; messages are not in the backup")
            else:
                for key in sorted(before["overwrites"].keys() | after["overwrites"].keys()):
                    left, right = before["overwrites"].get(key), after["overwrites"].get(key)
                    if left != right:
                        print(f"  #{after['name']} {key}")
                        for label, entry in (("before", left), ("after", right)):
                            print(f"    {label}: " + ("no overwrite" if entry is None else
                                  f"allow [{_permission_names(entry['allow'])}]; deny [{_permission_names(entry['deny'])}]"))
    for note in checks["notes"]:
        print("LIMIT:", note)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="ServerSentry guided one-shot fixer (preview by default)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--policy", type=Path, help="Preview a local explicit JSON policy")
    source.add_argument("--plan", type=Path, help="Revalidate a previously reviewed M2 plan")
    source.add_argument("--restore", type=Path, help="Prepare selected supported inverses from a local journal")
    parser.add_argument("--steps", help="Explicit journal step numbers to restore, e.g. 2,3")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Confirm and execute after preflight and backup")
    mode.add_argument("--preflight", action="store_true", help="Check and preview only (also the default)")
    parser.add_argument("--allow-destructive-sync", action="store_true")
    parser.add_argument("--allow-privilege-grants", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.restore) != bool(args.steps):
        parser.error("--restore requires --steps; --steps is only used with --restore")
    return args


async def main(argv=None) -> int:
    args = parse_args(argv)
    saved = None
    try:
        if args.policy:
            policy = load_policy(args.policy)
        elif args.plan:
            saved = read_json(args.plan)
            policy = validate_policy(saved.get("policy"))
        else:
            try:
                selected = [int(x.strip()) for x in args.steps.split(",")]
            except ValueError as exc:
                raise ValueError("--steps must be comma-separated integer step numbers") from exc
            policy, notes = restore_policy(read_json(args.restore), selected)
            for note in notes: print("RESTORE:", note)
        load_dotenv(HERE / ".env")
        token = os.getenv("DISCORD_TOKEN", "").strip()
        if not token:
            raise ValueError("DISCORD_TOKEN is missing from the local .env")
        guild_id = snowflake(os.getenv("GUILD_ID", "").strip(), "GUILD_ID")
        if "guild_id" in policy and str(policy["guild_id"]) != str(guild_id):
            raise ValueError("Policy/journal belongs to a different GUILD_ID")
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2
    intents = discord.Intents.none()
    intents.guilds = True
    client = discord.Client(intents=intents)
    member_ids = [a["user_id"] for a in policy["actions"] if a["type"] == "cleanup_member_overrides"]
    finished = False
    exit_code = 0

    async def refresh():
        return await fresh_guild(client, guild_id, member_ids)

    @client.event
    async def on_ready():
        nonlocal finished, exit_code
        if finished: return
        finished = True
        try:
            current = await refresh()
            options = {"destructive_sync": args.allow_destructive_sync, "grants": args.allow_privilege_grants}
            plan = check_saved_plan(saved, current, **options) if saved else build_plan(current, policy, **options)
            print_plan(plan)
            preview = save_private_json(OUTPUT, "plan", plan)
            print("Reviewed plan:", preview)
            if not args.apply:
                print("PREVIEW ONLY. No changes. Use --plan with this path and --apply after review.")
                return
            if not any(item["changed"] for item in plan["actions"]):
                print("No changes needed")
                return
            phrase = f"APPLY {guild_id}"
            if input(f"Type exactly {phrase} to execute this plan: ").strip() != phrase:
                print("Cancelled; no changes")
                return
            journal, run = await execute_plan(plan, refresh, OUTPUT, **options)
            for step in journal["steps"]:
                print(f"  #{step['plan']['index']}: {step['status']}" + (f" — {step['error']}" if step.get("error") else ""))
            print("Run:", journal["status"])
            print("Verification:", journal["verification"]["status"])
            print("Private journal:", run / "journal.json")
            if (run / "comparison.html").is_file():
                print("Before/after comparison:", run / "comparison.html")
            else:
                print("Comparison unavailable; inspect the journal's verification status/error")
            exit_code = 0 if journal["status"] == "completed" and journal["verification"]["status"] == "matches" else 1
        except Exception as exc:
            exit_code = 1
            print(f"FIXER ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            print("If execution started, inspect fixer_output/run_*/journal.json before any retry. No automatic rollback.", file=sys.stderr)
        finally:
            await client.close()

    try:
        async with client:
            await client.start(token, reconnect=False)
    except discord.LoginFailure:
        print("Invalid bot token; check the local .env", file=sys.stderr)
        return 1
    except discord.DiscordException as exc:
        print(f"Discord connection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("Interrupted. A submitted request may have completed; inspect the run journal.", file=sys.stderr)
        sys.exit(130)
