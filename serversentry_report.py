"""Self-contained offline HTML reports. Untrusted server content is always escaped."""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
from html import escape
import json
from pathlib import Path

from serversentry_compare import STATUS_LABELS
from serversentry_snapshots import validate_snapshot


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _json(value: object) -> str:
    return _e(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _options(items: dict[str, str]) -> str:
    return "".join(f'<option value="{_e(key)}">{_e(value)}</option>' for key, value in sorted(items.items()))


def _role_for(item: dict, roles: dict) -> str:
    finding = (item["after"] or item["before"])[0]
    return item.get("role_id") or (finding.get("target", "") if finding.get("target") in roles else "")


def _finding_card(item: dict, roles: dict, channels: dict) -> str:
    finding = (item["after"] or item["before"])[0]
    severity = item.get("severity_after") or item.get("severity_before") or finding["severity"]
    role_id, channel_id = _role_for(item, roles), item.get("channel_id", "")
    status = item["status"]
    context = []
    if role_id:
        context.append("Role: " + roles.get(role_id, role_id))
    if channel_id:
        context.append("Channel: #" + channels.get(channel_id, channel_id))
    source = item["after"] or item["before"]
    evidence = "".join(
        f'<p>{_e(f["details"])}</p><p class="recommendation"><strong>Next step</strong> {_e(f["recommendation"])}</p>'
        for f in source
    )
    before_after = ""
    if item["before"] and item["after"]:
        before_after = (
            '<details class="evidence"><summary>Before / after evidence</summary><div class="pair">'
            f'<div><h4>Before</h4><pre>{_json(item["before"])}</pre></div>'
            f'<div><h4>After</h4><pre>{_json(item["after"])}</pre></div></div></details>'
        )
    return (
        f'<article class="finding {_e(severity)}" data-severity="{_e(severity)}" '
        f'data-status="{_e(status)}" data-rule="{_e(finding["code"])}" '
        f'data-role="{_e(role_id)}" data-channel="{_e(channel_id)}">'
        '<details><summary><span class="finding-head">'
        f'<span class="badges"><span class="badge {_e(severity)}">{_e(severity.capitalize())}</span>'
        f'<span class="status">{_e(STATUS_LABELS.get(status, status))}</span></span>'
        f'<strong class="finding-title">{_e(finding["title"])}</strong>'
        f'<span class="context">{_e(" · ".join(context) or "Server-wide review")}</span>'
        f'<code>{_e(finding["code"])}</code></span></summary>'
        f'<div class="finding-body">{evidence}'
        f'<p class="note">{_e(item.get("note", ""))}</p>{before_after}</div></details></article>'
    )


def render_html(snapshot: dict, comparison: dict | None = None, baseline: dict | None = None) -> str:
    validate_snapshot(snapshot)
    roles = {r["id"]: r.get("name", r["id"]) for r in snapshot["roles"]}
    channels = {c["id"]: c.get("name", "Hidden channel") for c in snapshot["channels"]}
    if baseline:
        roles = {**{r["id"]: r.get("name", r["id"]) for r in baseline["roles"]}, **roles}
        channels = {**{c["id"]: c.get("name", "Hidden channel") for c in baseline["channels"]}, **channels}
    if comparison is None:
        items = [{"before": [], "after": [f], "severity_after": f["severity"], "status": "reported",
                  "role_id": f.get("role_id", ""), "channel_id": f.get("channel_id", "")}
                 for f in snapshot["findings"]]
    else:
        items = comparison["findings"]
    counts = Counter(f["severity"] for f in snapshot["findings"])
    hidden = sum(bool(c.get("obfuscated")) for c in snapshot["channels"])
    limits = list(snapshot["audit"].get("limitations", []))
    limits += comparison["limitations"] if comparison else [
        "Risk signals require review. No findings does not establish that the server is secure.",
        "Only the recorded channel inventory is inspected. Missing or hidden areas are not verified.",
    ]
    limits = list(dict.fromkeys(limits))
    limit_list = "".join(f'<li>{_e(x)}</li>' for x in limits)
    cards = "".join(_finding_card(x, roles, channels) for x in items)
    rule_options = _options({x["code"]: x["code"] for x in (f for item in items for f in (item["after"] or item["before"]))})
    status_options = _options({x["status"]: STATUS_LABELS.get(x["status"], x["status"].capitalize()) for x in items})
    finding_roles = {rid: roles.get(rid, rid) for x in items if (rid := _role_for(x, roles))}
    finding_channels = {x["channel_id"]: channels.get(x["channel_id"], x["channel_id"]) for x in items if x.get("channel_id")}
    changes_html = ""
    comparison_info = '<p class="muted">Single scan · compare two snapshots to see what changed.</p>'
    if comparison:
        comparison_info = (
            '<div class="timeline"><div><span>Baseline</span>'
            f'<strong>{_e(comparison["before"]["generated_at_utc"])}</strong></div>'
            '<span class="arrow" aria-hidden="true">→</span><div><span>Current scan</span>'
            f'<strong>{_e(comparison["after"]["generated_at_utc"])}</strong></div></div>'
        )
        comparison_info += '<div class="comparison-counts">' + "".join(
            f'<span><strong>{count}</strong> {_e(STATUS_LABELS.get(status, status))}</span>'
            for status, count in comparison["summary"].items()
        ) + '</div>'
        changes = []
        for change in comparison["changes"]:
            label = {"removed_or_unavailable": "Removed or unavailable", "not_comparable": "Coverage not comparable"}.get(
                change["status"], change["status"].capitalize())
            if change["kind"] == "channel" and change["status"] == "added":
                label = "Newly recorded"
            changes.append(
                '<details class="change"><summary>'
                f'<span class="badge neutral">{_e(label)}</span> '
                f'<strong>{_e(change["kind"].capitalize())}: {_e(change["name"])}</strong>'
                f'<span class="context">{_e(", ".join(change["fields"]))}</span></summary>'
                f'<p class="muted">ID: {_e(change["id"])}</p><div class="pair">'
                f'<div><h4>Before</h4><pre>{_json(change["before"])}</pre></div>'
                f'<div><h4>After</h4><pre>{_json(change["after"])}</pre></div></div></details>'
            )
        changes_html = (
            '<section id="changes"><div class="section-heading"><div><p class="eyebrow">Configuration</p>'
            f'<h2>Object changes <span class="count">{len(changes)}</span></h2></div></div>'
            '<p class="muted">Before / after values for changed fields. Missing channels may be deleted or unavailable. '
            'Member overwrite patterns are aggregate counts, not member identity comparisons.</p>'
            '<label class="change-search">Search changes<input id="change-search" type="search" placeholder="Role, channel or permission"></label>'
            '<p id="change-count" role="status"></p>'
            + ("".join(changes) or '<p class="empty">No object changes in the comparable recorded data.</p>')
            + '<p id="changes-empty" class="empty" hidden>No changes match your search.</p></section>'
        )
    inventory = ""
    for collection in ("roles", "channels"):
        rows = []
        for obj in snapshot[collection]:
            title = obj.get("name", "Hidden channel")
            if collection == "roles":
                detail = ', '.join(obj.get("guild_permissions", [])) or "No enabled server-wide permissions"
            else:
                detail = "Not fully inspected" if obj.get("obfuscated") else (
                    f'{obj.get("type", "channel")} · category sync: {obj.get("permissions_synced", "n/a")}'
                )
            rows.append(f'<tr><th scope="row">{_e(title)}</th><td><code>{_e(obj["id"])}</code></td><td>{_e(detail)}</td></tr>')
        inventory += (
            f'<details class="inventory"><summary>{collection.capitalize()} · {len(rows)}</summary>'
            '<div class="table-scroll"><table><thead><tr><th>Name</th><th>ID</th><th>Recorded permissions / coverage</th></tr></thead>'
            '<tbody>' + "".join(rows) + '</tbody></table></div></details>'
        )
    assets = Path(__file__).resolve().parent / "assets"
    css = (assets / "report.css").read_text(encoding="utf-8")
    script = (assets / "report.js").read_text(encoding="utf-8")
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode("ascii")
    server = snapshot["server"]
    title = "Permission changes" if comparison else "Permission review"
    changes_link = '<a href="#changes">Object changes</a>' if comparison else ''
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>ServerSentry · {_e(server["name"])}</title><style>{css}</style></head>
<body><a class="skip" href="#main">Skip to report</a><aside class="rail"><a class="brand" href="#overview">
<svg width="30" height="34" viewBox="0 0 30 34" aria-hidden="true"><path d="M15 2 28 7v10c0 7-5 12-13 15C7 29 2 24 2 17V7Z" fill="currentColor"/><path d="m9 17 4 4 8-10" stroke="white" stroke-width="3" fill="none"/></svg>
<span>ServerSentry<small>PERMISSION AUDIT</small></span></a><nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings</a>{changes_link}<a href="#inventory">Inventory</a><a href="#scope">Scope &amp; limits</a></nav>
<div class="rail-note"><strong>Local report</strong><p>No Discord changes.<br>No external requests.</p><p>Contains private server data.<br>Share with care.</p></div></aside>
<main id="main"><header id="overview"><p class="eyebrow">ServerSentry / {_e(server["name"])}</p><h1>{title}</h1>
<p class="lead">Understand the permissions. Review the evidence. Decide what needs attention.</p>
<div class="server-meta"><span>Server <code>{_e(server["id"])}</code></span><span>{len(snapshot["roles"])} roles</span><span>{len(snapshot["channels"])} recorded channels</span><span>Read-only audit</span></div>
{comparison_info}</header>
<div class="metrics" aria-label="Current scan summary"><div><span>Critical signals</span><strong>{counts['critical']}</strong><small>Review first</small></div><div><span>Warnings</span><strong>{counts['warning']}</strong><small>Check server intent</small></div><div><span>Information</span><strong>{counts['info']}</strong><small>Configuration context</small></div><div><span>Hidden channels</span><strong>{hidden}</strong><small>Not fully inspected</small></div></div>
<p class="scope-banner">Evidence has limits. This report covers the recorded data; it does not certify that the server is secure. <a href="#scope">Read the scope</a></p>
<section id="findings"><div class="section-heading"><div><p class="eyebrow">Review queue</p><h2>Findings <span class="count">{len(items)}</span></h2></div><button id="reset" type="button">Reset filters</button></div>
<noscript><p class="scope-banner">Enable JavaScript to filter this report. All findings and evidence remain readable below.</p></noscript>
<div class="filters"><label class="search-label">Search findings<input id="search" type="search" placeholder="Search titles, evidence or permissions"></label>
<label>Severity<select id="severity"><option value="">All severities</option><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select></label>
<label>Status<select id="status"><option value="">All statuses</option>{status_options}</select></label>
<label>Rule<select id="rule"><option value="">All rules</option>{rule_options}</select></label>
<label>Role<select id="role"><option value="">All roles</option>{_options(finding_roles)}</select></label>
<label>Channel<select id="channel"><option value="">All channels</option>{_options(finding_channels)}</select></label></div>
<p id="result-count" class="muted" role="status">{len(items)} finding groups</p><div id="finding-list">{cards}</div>
<p id="no-results" class="empty" {"" if not items else "hidden"}>{"No automated findings. Review the scope before drawing conclusions." if not items else "No findings match these filters. Try a broader search or reset the filters."}</p></section>
{changes_html}
<section id="inventory"><p class="eyebrow">Recorded scope</p><h2>Server inventory</h2><p class="muted">Server-wide role permissions are not the same as a member’s effective channel permissions.</p>{inventory}</section>
<section id="scope" class="scope"><p class="eyebrow">Before drawing conclusions</p><h2>Scope &amp; limits</h2><ul>{limit_list}</ul><dl><dt>Generated at (UTC)</dt><dd>{_e(snapshot['audit']['generated_at_utc'])}</dd><dt>Scan</dt><dd>{_e(snapshot['audit'].get('scan_id', 'Legacy export – not recorded'))}</dd><dt>Ruleset</dt><dd>{_e(snapshot['audit'].get('ruleset_version', 'Legacy export – coverage unknown'))}</dd></dl></section>
<footer>ServerSentry · Local evidence, explicit decisions. Reports contain server names, identifiers and permission mappings.</footer>
</main><script>{script}</script></body></html>'''
