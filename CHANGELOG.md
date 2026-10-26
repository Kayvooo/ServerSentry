# Changelog

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
