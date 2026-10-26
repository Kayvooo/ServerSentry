# Guided repairs, verification and selected recovery

M2 extends `discord_fix.py`. It remains a one-shot, explicit tool. Preview and the offline proposal assistant do not write to Discord. No new background bot is installed.

## 1. Choose changes

Start with a read-only audit:

```bash
python discord_audit.py
python serversentry.py suggest YOUR_AUDIT.json --output policy.suggested.json
```

The assistant displays original finding numbers. Choose supported findings and then the specific permission names to revoke. For an unattended **proposal only**, pass both choices explicitly:

```bash
python serversentry.py suggest YOUR_AUDIT.json --select 2 --revoke manage_roles --output policy.suggested.json
```

`--protect-role ROLE_ID` can be repeated. Administrator roles are automatically excluded/protected by the assistant. Managed/default/protected roles, short demo IDs and unsupported findings are not proposed. This first assistant supports `elevated_role_review` and selected revocations of Manage Server, Roles, Channels and Webhooks. It does not generate grants, guess private-channel intent or suggest mass synchronization.

The proposed JSON is editable and bound to the snapshot's server ID. A finding is a review signal; it does not establish that a permission should be removed. Review the proposal or write a policy using the existing recipes. Keep owner/high-admin and other sensitive role IDs in `protected_role_ids`.

## 2. Preflight and preview

```bash
python discord_fix.py --policy policy.suggested.json
```

`--preflight` is an explicit synonym for the default preview mode. The bot fetches current guild, role, channel and bot-member data through REST. Cleanup policies also fetch their named target members. Additional member listing, message content and privileged member intents are not required.

Checks cover the permissions needed by each endpoint, editable role hierarchy, managed/protected roles, missing/obfuscated channels, explicit destructive/grant opt-ins, required community channels and changes that would prevent later actions. For channel overwrites, role ordering is not treated as a general permission precedence rule.

Actions are projected in order without mutating Discord objects. Two changes to the same role/overwrite use the result of the first change as the second change's baseline. Category changes include synchronized children. Member-overwrite cleanup and mute visibility expand into separate journaled channel operations, so a partial run has a clear stopping point.

The REST adapter retains coverage flags and raw overwrite bits that some discord.py convenience objects omit. Named edits preserve unknown future bits; backups and fingerprints retain the full pair. Named permission explanations can only describe flags known to the installed library.

The preview prints named permissions before/after, overwrite allows/denies, changed role positions, affected channels and reasons. It saves `fixer_output/plan_<plan-id>.json`. If preflight fails, fix the cause and preview again; do not grant Administrator merely to bypass a missing permission.

## 3. Apply the reviewed plan

```bash
python discord_fix.py --plan fixer_output/plan_YOUR_PLAN_ID.json --apply
```

Use the same `--allow-privilege-grants` / `--allow-destructive-sync` flags that produced the plan. For example, a plan containing sensitive grants needs both the per-action `allow_privilege_grant:true` and the CLI grant flag. Clearing a privileged deny and permission aliases receive these checks too. Granting Administrator remains unsupported, including recovery.

The saved plan is checked against fresh data and rebuilt from its embedded policy. Modified actions, another server, a changed baseline or mismatched flags are refused. Direct `--policy ... --apply` still previews in the current session before asking for the exact `APPLY <guild-id>` phrase. A wrong phrase cancels without submitting a change.

Pre-M2 preview JSON files are not replayable M2 plans. Recreate the preview from the original explicit policy.

Confirmation authorizes the displayed plan, not later server changes. After confirmation, the tool reads the server again. The state fingerprint includes all recorded roles, channel overwrites/categories, bot role membership, owner and required community-channel IDs. Even unrelated recorded changes can invalidate a plan. This is deliberately conservative: regenerate and review instead of silently updating the plan.

## 4. Run artifacts and outcomes

Each execution writes private files under `fixer_output/run_<run-id>/`:

| File | Purpose |
| --- | --- |
| `backup.json` | Full recorded permission state, including raw overwrite target IDs. No messages. |
| `before/snapshot.json`, `report.md`, `report.html` | Fresh baseline audit and report. |
| `journal.json` | Reviewed plan and durable per-step status/timestamps/errors. |
| `after/snapshot.json`, `report.md`, `report.html` | Fresh final audit when available. |
| `comparison.json`, `comparison.html` | M1 before/after comparison when both audits succeed. |

The backup, baseline audit and initial journal must be saved before the first write. Every changed step is marked `in_progress` and persisted before its API call. Before each step, another REST read must match the projected reviewed state. After each submitted write, fresh REST data must match the expected result before another write is allowed. The final pass checks affected resources again and generates the audit/comparison.

Files are flushed before replacement, and POSIX directory metadata is synchronized as well. Windows lacks an equivalent portable directory-sync API; a storage or power failure still requires checking the actual server. The journal is evidence of observed progress, not a transactional guarantee.

| Step status | Meaning |
| --- | --- |
| `pending` | Not yet processed; may occur in an interrupted persisted file. |
| `unchanged` | Desired state already present; no request sent. |
| `in_progress` | Request may have been submitted; a crash can leave its outcome unknown. |
| `verified` | API call returned and fresh readback matched the reviewed projected state. |
| `blocked` | Stopped before this step's write, for example because the server changed. |
| `failed_outcome_unknown` | API call raised; the remote change may still have happened. |
| `verification_mismatch` | Readback differs from the expected state. |
| `unverified` | Post-write data could not be retrieved. |
| `journal_failed` | Journal persistence failed during a processed step; inspect before retrying. |
| `not_run` | Remaining step skipped after stopping. |

Overall `completed` requires completed steps and a successful final verification. `stopped`, `interrupted` or `verification_failed` is not success, even if some changes took effect. A zero exit code is reserved for successful execution, preview, cancellation or a no-change plan; failed/uncertain execution returns nonzero. The journal distinguishes these cases.

**No automatic rollback or resume occurs.** An HTTP error or timeout does not prove that Discord rejected the write. A crash or permanent disk failure may leave the last persisted journal at `in_progress`. Inspect the real server and local evidence before retrying. Permission backups do not contain deleted channels' messages.

## 5. Selected recovery

Choose explicit journal **step** numbers, which may differ from policy action numbers after expansion:

```bash
python discord_fix.py --restore fixer_output/run_YOUR_RUN_ID/journal.json --steps 1,2
```

This only previews a new inverse plan. After review, apply its saved plan with `--plan ... --apply`. Recovery that grants a privileged permission requires `--allow-privilege-grants` during both preview and apply. Restoring a formerly absent role overwrite removes it when it becomes empty; an originally present empty overwrite is preserved.

Supported steps are individually `verified` server-wide role permission changes and role overwrite changes, including primitive steps expanded from mute visibility. Selected steps are reversed newest first. Each inverse checks that the affected current role/overwrite still equals the verified original result; subsequent edits block recovery. Normal preflight, protected roles, confirmation, journal and verification apply again.

Deletion, messages, role moves, member-overwrite cleanup and whole-channel synchronization are not restored automatically. Unverified, interrupted or uncertain steps are refused. No inverse may grant Administrator. If one selected step is unsupported, proposal creation fails before any write; choose supported steps deliberately or handle the rest manually. This is targeted recovery, not a complete server restore.

## Limits and privacy

- REST reads and writes are not a Discord transaction. There is an unavoidable interval between checking and writing; the API does not provide a conditional permission-update lock. Immediate readback detects many mismatches but cannot prevent every race.
- The full fingerprint can stop on unrelated edits. Partially completed actions are not repeated automatically.
- Permission and audit checks cover recorded guild channels, not message content, all private threads or every member's combined-role access.
- A missing channel may be deleted or unavailable. The comparison preserves that uncertainty; a deletion step also has its API acknowledgement and journal context.
- Artifacts include private server names, IDs and permission mappings. Keep `fixer_output/`, policies and backups private. POSIX files are written with private modes; Windows relies on the account's folder permissions.
- `role_mute.py` remains a separate optional member-role operation. It does not acquire the M2 repair journal workflow merely by importing the private-file helper.

References: [Discord permission hierarchy and synchronization](https://github.com/discord/discord-api-docs/blob/main/developers/topics/permissions.mdx), [channel permission endpoints](https://github.com/discord/discord-api-docs/blob/main/developers/resources/channel.mdx), and [discord.py API reference](https://discordpy.readthedocs.io/en/stable/api.html).
