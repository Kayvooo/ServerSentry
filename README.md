# ServerSentry — Discord Security Audit & Permission Fixer

<p align="center"><img src="assets/serversentry-shield.svg" alt="ServerSentry Discord security auditor shield" width="180"></p>

**Audit Discord server permissions, detect risky roles, inspect channel overrides, and safely plan targeted repairs.** ServerSentry is a self-hosted Python CLI for server administrators. It runs **only when you start it**; no dashboard or always-on bot is needed.

**Two independent tools:**

- **Audit (`discord_audit.py`)** is strictly read-only. Exports detailed role/channel permission data and a Markdown risk report. No messages, passwords or bot tokens are collected in reports.
- **Fixer (`discord_fix.py`)** applies *only* explicit, server-local JSON policy actions. It checks current API data, previews sequential changes, protects administrator roles by default, makes a local backup and requires typed confirmation. Every write is journaled and read back; a final audit and comparison run automatically. It never automatically synchronizes every channel or guesses which special overrides are unnecessary.
- **Optional one-time role mute (`role_mute.py`)** replaces a member's assignable roles with a selected muted role and locally records the originals for manual restoration. It never installs a background watcher or creates per-member channel overrides.

> **Important:** Every server has its own permissions model. ServerSentry offers risk signals and explicit repair operations, **not** an autonomous permission-decision engine. A channel that is not synced may be intentionally configured for boosters, moderators, tickets or bots. Review each proposed change.

## Requirements

- Python 3.10+
- A Discord bot installed **on the target server**, configured with the permissions required for the operation
- For auditing: `View Channels` for the channels you want to inspect. A channel the bot cannot inspect will not be fully audited.
- For fixing: `Manage Roles` to edit roles, `Manage Roles` to edit channel overwrites, `Manage Channels` to delete/sync channels, and role hierarchy placement high enough to modify target roles. Do **not** grant Administrator unless strictly needed; remove extra permissions after the operation.
- The audit and fixer run with **guilds intent only**. No message-content or members intent is required for these one-time commands.

## Install

```bash
python -m pip install -r requirements.txt
cp .env.example .env
```

On Windows, use `py` instead of `python` and copy the example file in Explorer or run `copy .env.example .env` in CMD. Set local values in `.env`:

```dotenv
DISCORD_TOKEN=YOUR_NEW_TOKEN
GUILD_ID=YOUR_SERVER_ID
```

Get the guild ID from Discord with Developer Mode. **Never upload `.env` or a real policy file.** If a token is exposed, rotate it in the [Discord Developer Portal](https://discord.com/developers/applications). The old token is compromised even if it was intended to be temporary.

## 1. Run the read-only audit

```bash
python discord_audit.py
```

Results are written to `audit_output/` (ignored by Git):

- `server_audit_<guild-id>.json`: versioned snapshot with roles, raw channel overwrites and effective permission view of each **single** role.
- `server_report_<guild-id>.md`: warnings, recommendations and audit limitations.
- `server_report_<guild-id>.html`: an interactive local report with search, filters and expandable evidence.
- `history/<guild-id>/<scan-id>/`: a separate complete snapshot, Markdown report and HTML report for **every new audit**. Previous runs are retained; the familiar files above remain the latest exports.

The raw audit contains your server name, role names, channel names and Discord identifiers. It is **private output, not a sample to commit**. Member-specific overwrite targets are pseudonymized by the auditor. A real member with several roles can have different effective permissions from the single-role matrix.

### Try the report without a bot token

The offline commands use only Python's standard library. No installation, Discord connection or token is required for the demo:

```bash
python serversentry.py demo
```

Open `audit_output/demo.html` in your browser. The bundled examples are entirely synthetic. The report is self-contained: no hosting, login, external fonts, CDNs or telemetry. JavaScript enables filtering; the evidence remains readable without it.

### Compare two scans offline

Use two historical `snapshot.json` paths from the **same server**, oldest first:

```bash
python serversentry.py compare BEFORE.json AFTER.json --output audit_output/comparison.html --json-output audit_output/comparison.json
```

To render an existing export, including the original unversioned format:

```bash
python serversentry.py report YOUR_AUDIT.json --output audit_output/report.html
```

On Windows, substitute `py` for `python` and quote paths containing spaces. Findings are grouped by rule and target. Comparisons show permission changes, renames, added roles/channels and changes in severity. Missing or hidden channels are **not** automatically counted as fixed. Legacy exports do not record rule coverage, and member aliases cannot identify the same person across scans. See [reports and history](docs/reports.md) for status meanings, examples and limitations.

## 2. Configure targeted fixes

For supported elevated-role findings, an **offline assistant** can create revocation proposals. You choose the finding numbers and the exact permissions to revoke:

```bash
python serversentry.py suggest YOUR_AUDIT.json --output policy.suggested.json
```

It skips Administrator, managed, protected and default roles. It cannot infer private-channel intent or convert every finding into a fix. Review the generated JSON before using it. You can also write a policy manually:

Copy `config/policy.example.json` to `policy.json` and insert **your own Discord IDs locally**:

```json
{
  "version": 1,
  "protected_role_ids": ["YOUR_HIGH_ADMIN_ROLE_ID"],
  "actions": [
    {
      "type": "role_permissions",
      "role_id": "YOUR_REWARD_ROLE_ID",
      "revoke": ["mention_everyone"],
      "reason": "Reward roles should not ping everyone"
    }
  ]
}
```

`protected_role_ids` prevents **all fixer edits and moves** of those roles. Always put your owner/high-admin roles here. Administrator roles are also protected from permission changes unless explicitly opted in per action; granting the Administrator permission is not supported.

Preview:

```bash
python discord_fix.py --policy policy.json
```

Only after reviewing the local plan (`fixer_output/plan_*.json`), apply that exact saved plan:

```bash
python discord_fix.py --plan fixer_output/plan_YOUR_PLAN_ID.json --apply
```

You will have to type `APPLY <your guild ID>` **exactly**. The plan is rebuilt and checked against fresh REST data; stale plans require a new preview. Direct `--policy policy.json --apply` still previews and confirms in one invocation. Privileged-grant/destructive-sync flags must match those used to create a saved plan.

Before writing, the fixer saves a permission backup, baseline audit and durable journal to `fixer_output/run_<run-id>/`. It stops on errors, concurrent changes, mismatched readbacks or unavailable verification; **changes already made are not automatically rolled back**. An API timeout can have an unknown outcome. Review the journal and generated before/after comparison before retrying.

Selected, individually verified role/role-overwrite changes can be restored with another explicit preview and confirmation:

```bash
python discord_fix.py --restore fixer_output/run_YOUR_RUN_ID/journal.json --steps 1,2
```

This produces a new guarded plan. Use its saved path with `--plan ... --apply` after review. Restoring privileged grants still needs the extra opt-in. Channel deletion/messages, role moves, member-overwrite cleanup and whole-channel sync are not automatically restored. See [guided repairs](docs/repairs.md) for statuses, recovery limits and complete commands.

For supported fixes, permissions, and a protected channel synchronization recipe, see [Policy recipes](docs/policy-recipes.md).

## 3. Mutes without per-user channel overrides (optional)

Discord roles combine permissions: giving a muted role `View Channel = Deny` **does not guarantee invisibility** if the member still has another role that explicitly allows it. Discord timeout limits speaking/writing, but does not hide channels. A role-only mute can hide channels *only when other permission-granting roles have been removed* and the muted role's own permissions and category/unsynced channel overwrites are configured correctly.

A **one-time muted role visibility setup** is a policy action:

```json
{"type": "mute_role_visibility", "role_id": "YOUR_MUTED_ROLE_ID", "reason": "Hide channels from role-only muted members"}
```

It denies `View Channel` to that role on categories and **only** children with independent overwrites. It does **not** touch other role-specific overwrites, and it does not change any individual member override. Inspect the preview to confirm your muted role should not see *any* channel.

To manually replace/restores member roles when needed:

```bash
python role_mute.py --mute YOUR_MEMBER_ID --muted-role YOUR_MUTED_ROLE_ID
python role_mute.py --mute YOUR_MEMBER_ID --muted-role YOUR_MUTED_ROLE_ID --apply
python role_mute.py --unmute YOUR_MEMBER_ID --apply
```

Role originals are saved in `fixer_output/muted_role_state.json` **before** muting. Keep this state file securely or roles cannot be restored automatically. Owners, bot accounts, members with Administrator, and unmanageable/managed roles are rejected. This is deliberately **not** an automatic moderation bot; future mute events require a separate moderation integration.

## Security and privacy

- No real guild/user/role/channel ID, old token, private audit, backup, or member name is bundled in this project.
- `.env`, local `policy.json`, runtime exports, backups and muted state are gitignored. Backups contain sensitive IDs and permission mappings; protect or delete them locally as appropriate.
- All fixer actions are scoped to the **single** `GUILD_ID` supplied locally.
- The tool does not fetch message content, user DMs, or external telemetry.
- No permission changes happen merely by running the audit or fixer preview.
- The deletion and destructive synchronization actions are guarded; they are not recommended for bulk automatic use.
- The old version's continuous `--watch` mode and its per-member channel override mechanism are intentionally **not part of this release**.

## Supported actions

`role_permissions`, `channel_role_permissions`, `mute_role_visibility`, `cleanup_member_overrides`, `sync_channel`, `move_role_below`, `delete_channel`. See [docs/policy-recipes.md](docs/policy-recipes.md) for their prerequisites and caution notes.

## Testing

```bash
python -m unittest discover -s tests -v
python -m compileall -q discord_audit.py discord_fix.py role_mute.py serversentry.py serversentry_snapshots.py serversentry_compare.py serversentry_report.py serversentry_repair_model.py serversentry_repair_run.py serversentry_suggestions.py
```

Tests cover policy safety, repository sanitization, history, comparisons, reports and the audit callback. Synthetic REST tests also exercise sequential repairs, stale plans, journal failures, uncertain requests, verification, restore guards and confirmation. CI checks selected Python versions on Linux and Windows, plus browser report behavior. They cannot establish that live Discord permissions will match your server's intent. Start with a separate test server. See [contributing](CONTRIBUTING.md) for development and optional browser checks.

## License

Licensed under **PolyForm Noncommercial 1.0.0**; see [LICENSE](LICENSE). You can inspect, modify and redistribute for noncommercial purposes, but commercial use requires separate permission. **This is source-available software, not OSI-approved Open Source.**
