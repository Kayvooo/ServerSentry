# Policy recipes — explicit, reviewed fixes

Copy `config/policy.example.json` to **local** `policy.json`. Add the actions below under `actions` with real IDs you copied from Discord. These are illustrative placeholders, not live targets. Test on a staging server and review `--plan`/default-preview before applying. `protected_role_ids` must include every high-admin or other role you never want changed.

## Revoke excessive role permissions

```json
{"type":"role_permissions", "role_id":"ROLE_ID", "revoke":["mention_everyone"], "reason":"Reward role shouldn't mass ping"}
```

For an administrator role, the default protection rejects edits. To explicitly remove Administrator from a **non-protected** role, configure `"allow_admin_role_edit":true` on that single action. No action may grant Administrator. Managed integration roles cannot have their guild permissions edited by this tool.

## Patch one role override without erasing other special rules

```json
{"type":"channel_role_permissions", "channel_id":"CHANNEL_ID", "role_id":"ROLE_ID", "set":{"view_channel":true,"send_messages":false}, "reason":"Staff announcements: view but don't post"}
```

Only the named permission keys change. All other settings for that role, other roles (including booster and bot roles), and per-member overrides remain untouched.

Allowing or clearing a deny for privileged flags also requires `allow_privilege_grant:true` and `--allow-privilege-grants`. Permission aliases receive the same checks. An overwrite on a category also affects currently synchronized children; the M2 plan lists those effects.

## Make the muted role unable to see channels

```json
{"type":"mute_role_visibility", "role_id":"MUTED_ROLE_ID", "reason":"Mute visibility baseline"}
```

This adds role-specific `view_channel:false` on **categories** and independently customized child channels only. Already-synced children continue to inherit their parent category; customized booster/ticket/bot exceptions stay as they were. Members must not retain other roles granting `view_channel:true`, or they may still see channels.

## Remove old personal overwrites for exactly one member

```json
{"type":"cleanup_member_overrides", "user_id":"USER_ID", "reason":"Remove legacy member-level visibility rules"}
```

This permanently removes **all** user-specific overwrites for that user, including legitimate exceptions. A local backup is created before applying; nothing is uploaded. The member must still belong to the server.

## Move a non-admin, non-managed bot role below another role

```json
{"type":"move_role_below", "role_id":"BOT_ROLE_ID", "anchor_role_id":"ANCHOR_ROLE_ID", "reason":"Move utility bot below moderation roles"}
```

Role hierarchy matters for moderation bots: putting them below the roles they need to manage may break them. This operation changes relative ordering only. It refuses to move Administrator or managed roles, and refuses roles included in `protected_role_ids`. No automatic classification of bots is performed.

## Synchronize a child channel to its category

```json
{"type":"sync_channel", "channel_id":"CHANNEL_ID", "reason":"Remove redundant inherited overrides"}
```

**Important:** Synchronization can erase custom permissions. By default ServerSentry refuses synchronization when the child's raw overwrites differ from the category, even if both currently produce the same effective access.

If and *only if* you have manually inspected every different overwrite and intend to delete them, add `"allow_overwrite_loss":true` **to that action** and invoke the fixer with `--allow-destructive-sync`. The plan prints a destructive warning. Never apply this across all unsynced channels automatically. Prefer targeted `channel_role_permissions` instead.

## Delete a specific channel

```json
{"type":"delete_channel", "channel_id":"CHANNEL_ID", "confirm_name":"exact-current-name", "allow_delete":true, "reason":"Unused empty test channel"}
```

Deletes channel contents irreversibly (the permissions backup does not back up messages). A category with children is refused. Specify each target by exact ID and name. This operation requires typed confirmation on the whole fix plan.

## Give a role sensitive privileges

For `kick_members`, `ban_members`, `manage_roles`, etc., the action must include `"allow_privilege_grant":true` and the CLI must include `--allow-privilege-grants`. Review privilege escalation separately; no name-based heuristic should silently grant powers.

## Apply and verify

1. Set your local `.env`, including `GUILD_ID`.
2. Run `python discord_audit.py` to make an initial snapshot.
3. Run `python discord_fix.py --policy policy.json` to preview actions. If errors occur, revise the policy rather than bypass checks.
4. Run `python discord_fix.py --plan YOUR_SAVED_PLAN.json --apply` with the same privileged/destructive flags and enter the exact confirmation phrase. Direct `--policy ... --apply` is also supported.
5. Review the automatically generated journal, fresh before/after audits and comparison under `fixer_output/run_<run-id>/`. A mismatch or unknown API outcome stops the remaining steps.
6. Use the [guided repair instructions](repairs.md) for selected supported recovery. Keep local backups private and remove excess bot privileges when finished.

There is no 24/7 process or change-monitoring watcher.
