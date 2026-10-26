# Changelog

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
