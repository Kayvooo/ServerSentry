# Rule reference

Every finding in a report has a stable `code`. This page explains what each rule looks at, why it matters, how
severe it is and what it **cannot** tell you. Findings are risk signals. They are never confirmed vulnerabilities,
and no rule guesses intent from names, except the clearly labelled name hint below.

Ruleset **2** (current) adds the server-settings, hierarchy, override and channel rules marked "ruleset 2". When
you compare scans made with different rulesets, a finding that disappeared is reported as *cannot verify*, not as fixed.

To say that something is intended, use [expectations and accepted risks](expectations.md).

## Ruleset 1

### `everyone_global_elevated`
**Severity:** critical for Administrator, Manage Server/Roles/Channels/Webhooks, otherwise warning.
@everyone applies to every member, so powerful server-wide permissions on it reach everyone.
Scope: server-wide role flags only; channel overrides are covered by other rules.
Fixer: not editable by design (the fixer refuses @everyone). Change it in Discord.

### `elevated_role_review`
**Severity:** warning. A role has Administrator or Manage Server/Roles/Channels/Webhooks.
Scope: the member-to-role assignment is not collected, so the report cannot say who holds the role.
Fixer: supported through `serversentry.py suggest`.

### `channel_obfuscated`
**Severity:** warning. Discord hid the channel's metadata from the bot, so it was not audited.
Give the bot View Channel there and rerun. Never counted as fixed when it disappears.

### `conflicting_overwrite`
**Severity:** info. An override denies View Channel but allows sending or connecting. Other roles may change the result.
Member targets are pseudonyms that change on every scan.

### `sensitive_channel_visible_to_everyone`
**Severity:** warning. **Name hint only.** A channel or category name suggests an internal area (for example "staff" or "logs")
while @everyone can view it. A name cannot prove purpose; use an expectation to state the real intent.

### `everyone_channel_moderation`
**Severity:** critical for Manage Roles/Webhooks, otherwise warning. @everyone holds Manage Channels/Webhooks/Roles/Messages in a viewable channel.

### `individual_member_overrides`
**Severity:** info. A channel has member-specific overrides. Often intentional (tickets); review for stale exceptions.

### `unsynced_channels`
**Severity:** info. Aggregate count of channels that differ from their category. Differences may be intentional.

### `audit_bot_admin`
**Severity:** warning. The audit bot itself has Administrator. Auditing is read-only, but leaked credentials would not be.

## Ruleset 2

### `server_verification_low`
**Ruleset 2.** **Severity:** warning for "none", info for "low". New accounts can join and write immediately.
Scope: gateway-provided setting only; it says nothing about other anti-raid tools.

### `server_content_filter_off`
**Ruleset 2.** **Severity:** info. Discord's explicit media filter is disabled. Intentional on some servers.

### `server_mfa_not_required`
**Ruleset 2.** **Severity:** warning. "Require 2FA for moderation" is off while human roles with powerful permissions exist.
Bots are exempt from 2FA and ignored by this rule.

### `role_hierarchy_escalation`
**Ruleset 2.** **Severity:** critical if the lower role has Administrator, otherwise warning.
Members with Manage Roles can generally assign roles below their own highest role. If a role below one with Manage Roles
carries powerful permissions the higher role does not already hold, its members may be able to hand those permissions out.
Roles managed by integrations are ignored because they cannot be assigned by hand.
Scope: role order and permission flags only. The tool does not know who holds which role. Verify the order in Discord.

### `role_channel_management_override`
**Ruleset 2.** **Severity:** warning. A non-@everyone role is allowed Manage Roles, Webhooks or Channels in a channel override.
That lets holders change access or post through webhooks in that channel. Channels synchronized with a category are reported once, at the category.
Roles with Administrator are skipped because overrides do not limit them.
Fixer: supported through `serversentry.py suggest`; the proposal explicitly denies the selected permission for that role in that channel.

### `role_moderation_review`
**Ruleset 2.** **Severity:** info; warning for bot/integration roles with Ban, Kick, Timeout or Mention Everyone, because a leaked bot token inherits them.
Roles already covered by `elevated_role_review` are skipped.

### `everyone_channel_mention_everyone`
**Ruleset 2.** **Severity:** warning. @everyone may mention everyone in a viewable channel through an override, although the server-wide flag is off.

### `everyone_voice_moderation`
**Ruleset 2.** **Severity:** warning. @everyone may mute, deafen or move members in a viewable channel.

### `announcement_open_posting`
**Ruleset 2.** **Severity:** warning. @everyone can send messages in an announcement channel, whose messages can be published to followers.

## Declared expectations

### `expectation_violated`
**Ruleset 2.** Severity is chosen by you per expectation (default warning). Something you declared is not true. See [expectations](expectations.md).

### `expectation_unverifiable`
**Ruleset 2.** **Severity:** warning. An expectation could not run, for example because its role or channel is not in the scan, or the setting was not recorded.
A check that cannot run is not a passing check, so this is never silent.
