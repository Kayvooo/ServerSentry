#!/usr/bin/env python3
"""Optional one-shot role mute/unmute; never sets member-specific channel overwrites.

Use only when the mute system's role settings are already configured. An external
moderation bot is needed for automated future mute/unmute events.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone

import discord
from dotenv import load_dotenv
from discord_fix import snowflake, save_private_json, OUTPUT, HERE

STATE = OUTPUT / "muted_role_state.json"


def load_state(guild_id: int):
    if not STATE.exists():
        return {"version": 1, "guild_id": str(guild_id), "members": {}}
    state = json.loads(STATE.read_text(encoding="utf-8"))
    if state.get("guild_id") != str(guild_id) or state.get("version") != 1:
        raise RuntimeError("State belongs to a different guild/version; refusing")
    return state


def save_state(data):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, STATE)
    if os.name != "nt": STATE.chmod(0o600)


def checked_member(member, me):
    if member.id == member.guild.owner_id or member.bot or member.guild_permissions.administrator:
        raise RuntimeError("Owner, bots and administrators cannot be muted")
    if member.top_role >= me.top_role:
        raise RuntimeError("Bot's top role must be above every target role")
    if not me.guild_permissions.manage_roles:
        raise RuntimeError("Bot needs Manage Roles")


async def process(guild, me, args):
    member = await guild.fetch_member(args.mute or args.unmute)
    checked_member(member, me)
    state = load_state(guild.id)
    key = str(member.id)
    if args.mute:
        muted = guild.get_role(snowflake(args.muted_role, "muted_role"))
        if muted is None or muted.managed or muted.permissions.administrator or muted >= me.top_role:
            raise RuntimeError("Muted role is missing, privileged or too high")
        originals = [r for r in member.roles if not r.is_default() and r.id != muted.id]
        if any(r.managed or r >= me.top_role or r.permissions.administrator for r in originals):
            raise RuntimeError("Member has a managed/high/admin role; cannot remove it safely")
        if key in state["members"]:
            raise RuntimeError("Already has a pending role restore; refusing to replace original roles")
        print(f"MUTE {key}: save {len(originals)} original roles, replace with muted role")
        if not args.apply:
            print("PREVIEW ONLY")
            return
        if input(f"Type MUTE {key}: ").strip() != f"MUTE {key}":
            print("Cancelled")
            return
        state["members"][key] = {"role_ids":[str(r.id) for r in originals],
                                   "muted_role_id":str(muted.id),
                                   "saved_at":datetime.now(timezone.utc).isoformat()}
        save_state(state)  # Must persist originals BEFORE any Discord edit.
        await member.edit(roles=[muted], reason="ServerSentry one-shot role mute")
    else:
        rec = state["members"].get(key)
        if rec is None:
            raise RuntimeError("No local saved roles. Restore manually, do not guess")
        if not any(r.id == int(rec["muted_role_id"]) for r in member.roles):
            raise RuntimeError("Member no longer has recorded mute role; manual review required")
        restored = []
        for rid in rec["role_ids"]:
            r = guild.get_role(int(rid))
            if r is None or r.managed or r >= me.top_role or r.permissions.administrator:
                raise RuntimeError(f"Role {rid} disappeared, managed, high or admin; manual review")
            restored.append(r)
        print(f"UNMUTE {key}: restore {len(restored)} roles from local state")
        if not args.apply:
            print("PREVIEW ONLY")
            return
        if input(f"Type UNMUTE {key}: ").strip() != f"UNMUTE {key}":
            print("Cancelled")
            return
        await member.edit(roles=restored, reason="ServerSentry one-shot role unmute")
        del state["members"][key]
        save_state(state)
    print("Done. No member channel overwrites changed.")


async def main():
    p = argparse.ArgumentParser(description="Manual one-shot role mute/unmute; no watcher")
    exclusive = p.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("--mute", help="Member ID to mute")
    exclusive.add_argument("--unmute", help="Member ID to restore")
    p.add_argument("--muted-role", help="Muted role ID, required when muting")
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()
    if args.mute and not args.muted_role:
        p.error("--mute needs --muted-role")
    snowflake(args.mute or args.unmute, "user_id")
    if args.muted_role: snowflake(args.muted_role, "muted_role_id")
    load_dotenv(HERE / ".env")
    token, raw = os.getenv("DISCORD_TOKEN", "").strip(), os.getenv("GUILD_ID", "").strip()
    if not token: raise ValueError("Missing local DISCORD_TOKEN")
    guild_id = snowflake(raw, "GUILD_ID")
    intents = discord.Intents.none(); intents.guilds = True
    client = discord.Client(intents=intents)
    completed = False
    error = None

    @client.event
    async def on_ready():
        nonlocal completed, error
        if completed: return
        completed = True
        try:
            guild = client.get_guild(guild_id)
            if guild is None: raise RuntimeError("Guild not found")
            me = guild.me or await guild.fetch_member(client.user.id)
            await process(guild, me, args)
        except Exception as exc:
            error = exc
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        finally:
            await client.close()

    async with client:
        await client.start(token, reconnect=False)
    return 1 if error else 0


if __name__ == "__main__":
    try: sys.exit(asyncio.run(main()))
    except KeyboardInterrupt: sys.exit(130)