# Synthetic report examples

`before.json` and `after.json` describe an invented server. All names, IDs, findings and scan metadata are synthetic. Short numeric IDs intentionally differ from production Discord identifiers.

Run `python serversentry.py demo` from the repository root and open `audit_output/demo.html`.

Expected finding groups:
- 1 newly reported finding.
- 2 still reported findings.
- 1 changed severity.
- 2 no longer detected findings.
- 1 finding that cannot be verified because channel visibility was lost.
- 1 group involving member aliases that cannot be compared individually.

The examples also include role/channel renames, changed permissions, a new channel and aggregate member overrides. They illustrate comparison behavior; they are not a complete live Discord capture.
