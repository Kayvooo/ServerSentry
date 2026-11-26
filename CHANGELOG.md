# Changelog

## Unreleased – M3 + M4

- **Ruleset 2 (M3):** server settings (verification level, media filter, 2FA for moderation), role-hierarchy escalation
  (Manage Roles above more powerful roles), management overrides for ordinary roles in channels, moderation permissions
  of roles and bots, @everyone mentioning/voice moderation per channel, and open posting in announcement channels.
  Rules work on plain snapshot data, so they are testable offline. Every code is documented in `docs/rules.md`.
- **Expectations (M4):** `expectations.json` states what must be true (`role_must_lack`, `permission_allowlist`,
  `channel_visible_only_to`, `server_setting_in`). Violations become findings; checks that cannot run are reported, never silent.
- **Accepted risks (M4):** a finding can be accepted with a reason and a mandatory expiry date. It stays in the data,
  is marked in reports and comparisons, and reopens after the date. Unused and expiring entries are listed.
- `suggest` also proposes denying a role's channel management override (an explicit deny, so no privileged-grant opt-in).
- `report` and `compare` accept `--expectations`; the demo now shows expectations and accepted risks.
- **New report design:** dark/light themes, severity overview, filters by severity/state/rule/role/channel, copyable next-step
  commands, expectation and accepted-risk section, printable layout, project and documentation links. Still one offline file
  without external requests.
- Markdown export marks accepted risks and links to the rule reference.
- Fix: View Channel is reported by discord.py as `read_messages`. `conflicting_overwrite` never fired on live data for this reason.
  Expectations accept both spellings (and the other Discord UI aliases).
- Ruleset version is now `2`. Comparing scans across rulesets reports vanished findings as *cannot verify*, never as fixed.

## Unreleased – M2

- Add an offline assistant for explicitly selected elevated-role permission revocations.
- Preflight against fresh REST role/channel/member data and project dependent actions in order.
- Bind saved plans to the reviewed state and require matching privilege/destructive flags.
- Check hierarchy, bot permissions, protected targets and category effects before writing.
- Save backups, baseline audit and a durable per-step journal before submitting changes.
- Read back every write, stop on mismatches or unknown outcomes, and create a final audit/comparison.
- Generate guarded inverse plans for selected individually verified role/role-overwrite steps.
- Test partial execution, concurrent edits, lost responses, cancellation, journal failures, verification and recovery using real discord.py objects with a synthetic REST adapter.

## Unreleased – M1

- Keep separate versioned historical snapshots and reports for every new audit.
- Preserve the original latest JSON/Markdown paths and add a local HTML report.
- Add token-free `demo`, `report` and `compare` commands using the standard library.
- Compare permission changes by stable role/channel IDs and classify finding groups conservatively.
- Retain uncertainty for missing channels, legacy coverage and per-scan member aliases.
- Add an offline report with search, filters, expandable evidence, object changes and scope limits.
- Add synthetic examples, report/history documentation and contribution instructions.
- Exercise the real audit callback with a synthetic guild and expand comparison, persistence and escaping tests.
- Extend CI to selected Linux/Windows Python versions and optional browser regression checks.
