# Local reports, scan history and comparisons

The existing `python discord_audit.py` command still runs a single read-only audit. New audits create JSON, Markdown and interactive HTML, and retain each complete run locally.

## Try the demo

```bash
python serversentry.py demo
```

Open `audit_output/demo.html`. No token, connection or third-party Python packages are needed. The example changes include a renamed role/channel, revoked permissions, a changed severity, a newly recorded channel and a channel whose visibility is lost. Everything in `examples/` is synthetic.

## Files and privacy

```text
audit_output/
  server_audit_<guild-id>.json
  server_report_<guild-id>.md
  server_report_<guild-id>.html
  history/<guild-id>/<scan-id>/
    snapshot.json
    report.md
    report.html
```

The top-level files are the most recent exports. Each history directory is exclusive to one scan; a later run does not overwrite it. A completed historical run contains `snapshot.json`, written after its reports. No automatic history pruning is performed in this milestone.

Files are replaced atomically one at a time. Latest JSON/Markdown/HTML are not a transaction: if an update fails partway through, some latest aliases may refer to different runs. The complete historical directory is authoritative. Incomplete new history directories are removed on handled write errors. A process crash may leave an incomplete directory; do not use it as a completed scan.

On POSIX systems, audit directories use mode 700 and written files use mode 600. On Windows, protect the output directory with your account's filesystem permissions. Moving or sharing a file can change its access protections. Offline reports written with `--output` do not change the permissions of an existing parent directory.

All outputs can contain server names, channel names, role names, identifiers and permissions. Keep them private. Do not commit reports, real policies, `.env`, member state or backups. A self-contained HTML file includes the evidence shown inside it, even when details are collapsed.

## Compare saved exports

```bash
python serversentry.py compare BEFORE.json AFTER.json --output audit_output/comparison.html
```

Optionally add `--json-output audit_output/comparison.json`. Both inputs must belong to the same server. Explicit input order defines baseline and current scan; the tool does not select or reorder them for you. Quote paths with spaces, especially on Windows. Use `py` instead of `python` if that is your launcher.

You can copy the paths printed after an audit and append `/snapshot.json` to each history directory. Use different output paths from the inputs. Offline output files are replaced if they already exist; input snapshots are protected against accidental overwriting.

Roles/channels are matched by IDs, so a rename remains the same object. The comparison ignores timestamps, scan IDs, list ordering and redundant permission bitfield representations. It compares server-wide role permissions, role positions, category IDs, synchronization, role channel overwrites, recorded effective single-role permissions and aggregate member-overwrite patterns.

## Finding statuses

| Status | Meaning |
| --- | --- |
| Newly reported | Present now, absent from the baseline; may also reflect changed rules or visibility. |
| Still reported | Same rule and target are still reported with the same severity. Evidence can differ; expand it to inspect before/after. |
| Severity changed | Same rule and target are reported with a different severity. |
| No longer detected | The finding is absent under the same recorded ruleset and relevant scope. This is not a security guarantee. |
| Cannot verify | A target is missing/hidden, or rule coverage cannot be established. |
| Role removed | The role is absent from the later role inventory; this is not a repaired permission. |
| Member aliases cannot be compared | Per-scan member aliases cannot reliably refer to the same person. |

Finding counters represent **rule/target groups**, not people or confirmed vulnerabilities. The summary strip shows raw finding counts from the current scan; a comparison can include older findings as well.

Missing channels are shown as **removed or unavailable**. The cached inventory cannot establish whether a channel was deleted or became inaccessible. Hidden channel details are excluded from permission comparisons. Aggregate visibility/synchronization findings are not cleared when relevant inventory coverage changes.

A channel appearing for the first time is **newly recorded**. It may have been created or may simply have become visible to the bot.

Individual member overwrites are compared only as channel-level counts and permission-pattern counts. A different pattern indicates a configuration change, not which member changed. Swapping equally configured members can be invisible. `member_1` in one scan is not a stable identity for another scan.

## HTML report

Search titles, evidence and recommendations, and combine severity, status, rule, role and channel filters. Reset restores all findings. Open a finding to read evidence, next steps and available baseline/current details. Object changes have a separate search. The inventory and scope sections remain available even when there are no findings.

The file uses no network services. Server-supplied names and findings are escaped as text. A restrictive content security policy blocks network access and permits only the bundled report script. Filtering uses JavaScript; the initial content and native expandable evidence are still readable with scripting disabled.

## Snapshot format and compatibility

Version 1 records `audit.schema_version`, `tool_version`, `scan_id`, `ruleset_version`, `rules_checked` and the channel-inventory method alongside the original export data. Existing fields remain available. New scans use unique random scan IDs. Rule identifiers and object IDs provide finding identity; display titles are not identity keys.

Original exports without `schema_version` can be rendered and compared. Their missing rule coverage is kept unknown; it is not filled in retroactively. Unsupported schema versions, duplicate object IDs, malformed required data and comparisons between different servers fail with an error. A ruleset change prevents absent findings from being labeled as no longer detected.

When modifying rule semantics, update `RULESET_VERSION` in `serversentry_snapshots.py`; keep `RULE_CODES` aligned with the rules actually run by the auditor. A schema change must either preserve the version 1 reader contract or introduce an explicit supported-version path.

## Limits

These are permission risk signals, not a complete security assessment. Channel-name checks are heuristics. Owner privileges, combinations of multiple roles, private threads, message content and member assignments are not fully represented by the single-role matrix. The fixer and any Discord writes are outside these offline commands.
