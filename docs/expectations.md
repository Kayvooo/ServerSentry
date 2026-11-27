# Expectations and accepted risks

Reports list risk signals. Only you know which of them are intended. Instead of guessing from names, ServerSentry lets you
write your intent down once, in a local file, and then checks it on every audit.

* **Expectations** declare what must be true. A violation becomes a finding (`expectation_violated`).
* **Accepted risks** mark a finding as reviewed. They need a **reason** and an **expiry date**, so an exception cannot live forever.

Copy `config/expectations.example.json` to `expectations.json` in the project folder. The audit uses it automatically.
Replace the `YOUR_..._ID` placeholders with the numeric IDs from Discord (Developer Mode); the file is rejected while placeholders remain.
The file contains your server IDs and is gitignored. Do not publish it.

```json
{
  "version": 1,
  "expectations": [
    {"id": "staff-private", "type": "channel_visible_only_to", "channel_id": "YOUR_STAFF_CHANNEL_ID",
     "role_ids": ["YOUR_HELPER_ROLE_ID"], "severity": "critical", "reason": "Moderation discussions"},
    {"id": "helpers-no-role-admin", "type": "role_must_lack", "role_id": "YOUR_HELPER_ROLE_ID",
     "permissions": ["manage_roles"]},
    {"id": "who-manages-roles", "type": "permission_allowlist", "permission": "manage_roles",
     "role_ids": ["YOUR_ADMIN_ROLE_ID"]},
    {"id": "verify-members", "type": "server_setting_in", "setting": "verification_level",
     "allowed": ["medium", "high", "highest"]}
  ],
  "accepted_risks": [
    {"code": "individual_member_overrides", "channel_id": "YOUR_TICKET_CHANNEL_ID",
     "reason": "Ticket channel: per-member overrides are the workflow", "expires": "2027-03-31"}
  ]
}
```

## Expectation types

| type | fields | violated when |
| --- | --- | --- |
| `role_must_lack` | `role_id`, `permissions` | the role has any listed server-wide permission |
| `permission_allowlist` | `permission`, `role_ids` | a role not on the list holds the permission (@everyone included) |
| `channel_visible_only_to` | `channel_id`, `role_ids` | @everyone, or a role not on the list, can view the channel |
| `server_setting_in` | `setting`, `allowed` | the server setting has another value |

Settings: `verification_level` (none, low, medium, high, highest), `explicit_content_filter` (disabled, no_role, all_members),
`mfa_level` (disabled, require_2fa), `default_notifications` (all_messages, only_mentions).

Optional on every expectation: `severity` (`critical`, `warning` or `info`, default warning) and `reason`, which is shown in the report.

Notes and limits:

* The file is validated completely before anything runs. Unknown keys, permissions or settings are errors, never silently ignored.
* `channel_visible_only_to` uses the single-role matrix (@everyone plus one role plus overrides). Roles with Administrator always see
  every channel; they are reviewed by `elevated_role_review` and are not listed here. Individual member overrides are not evaluated.
* An expectation whose role, channel or setting is not in the scan produces `expectation_unverifiable`, never a silent pass.

## Accepted risks

An entry matches findings by `code` plus any of `role_id`, `channel_id` and `target` that you list. All listed fields must match.

* The finding **stays** in the JSON, the comparison and the report, marked *Accepted* with your reason.
  It no longer counts in the open totals.
* After `expires` has passed, the finding counts as open again and the report says so.
* Expiry is judged on the **scan date**, so re-rendering an old report never changes what it said.
* The report lists acceptances that expire within 30 days and acceptances that matched nothing, so the file stays clean.
* Member aliases in findings change per scan. Accept those findings by `code` and `channel_id` only.

## Offline use

```bash
python serversentry.py report audit.json --output report.html --expectations expectations.json
python serversentry.py compare BEFORE.json AFTER.json --output comparison.html --expectations expectations.json
```

Both scans are evaluated with the same file. Expectation findings appear in comparisons like any other finding.
If only the newer scan was evaluated with expectations, their violations appear as *newly reported*, because the earlier scan did not check them.
In the opposite order, violations missing from the newer scan are *cannot verify*, never *no longer detected*.
