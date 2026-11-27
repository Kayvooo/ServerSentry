"""Self-contained offline HTML reports. Untrusted server content is always escaped.

The page makes no network requests: styles, script and icons are inline and a CSP forbids anything
else. Links to the project are plain anchors that only load when the reader clicks them.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
from html import escape
import json
from pathlib import Path

from serversentry_compare import STATUS_LABELS
from serversentry_links import COMMUNITY_URL, DOC_LINKS, DOCS_URL, PROJECT_LINKS, REPO_URL, rule_url
from serversentry_rules import RULE_INFO
from serversentry_snapshots import validate_snapshot

STATE_LABELS = {"open": "Open", "accepted": "Accepted risk", "expired": "Acceptance expired"}

# Lucide-style 24px stroke icons, inlined once and referenced with <use>.
_ICONS = {
    "shield": '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"/><path d="m9 12 2 2 4-4"/>',
    "critical": '<path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    "warning": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    "info": '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    "eye-off": '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.53 13.53 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><path d="m2 2 20 20"/>',
    "check": '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/>',
    "github": '<path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/>',
    "book": '<path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    "moon": '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "chevron": '<path d="m6 9 6 6 6-6"/>',
    "copy": '<rect width="13" height="13" x="9" y="9" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    "external": '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    "lock": '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
}
_SPRITE = ('<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>'
           + "".join(f'<symbol id="i-{name}" viewBox="0 0 24 24">{body}</symbol>' for name, body in _ICONS.items())
           + "</defs></svg>")


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _json(value: object) -> str:
    return _e(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _icon(name: str, extra: str = "") -> str:
    return f'<svg class="icon {extra}" aria-hidden="true" focusable="false"><use href="#i-{name}"/></svg>'


def _when(stamp: object) -> str:
    text = str(stamp)
    return text[:16].replace("T", " ") + " UTC" if len(text) >= 16 and text[10:11] == "T" else text


def _options(items: dict[str, str]) -> str:
    return "".join(f'<option value="{_e(key)}">{_e(value)}</option>' for key, value in sorted(items.items()))


def _role_for(item: dict, roles: dict) -> str:
    finding = (item["after"] or item["before"])[0]
    return item.get("role_id") or (finding.get("target", "") if finding.get("target") in roles else "")


def _link(label: str, url: str, icon: str = "external") -> str:
    return f'<a href="{_e(url)}" target="_blank" rel="noopener noreferrer">{_e(label)}{_icon(icon)}</a>'


def _item_state(item: dict) -> tuple[str, dict | None]:
    for finding in item["after"]:
        if finding.get("accepted"):
            return "accepted", finding["accepted"]
    for finding in item["after"]:
        if finding.get("acceptance_expired"):
            return "expired", finding["acceptance_expired"]
    return "open", None


def _finding_card(item: dict, roles: dict, channels: dict, comparing: bool) -> str:
    source = item["after"] or item["before"]
    finding = source[0]
    severity = item.get("severity_after") or item.get("severity_before") or finding["severity"]
    role_id, channel_id = _role_for(item, roles), item.get("channel_id", "")
    status = item["status"]
    state, mark = _item_state(item)
    context = []
    if role_id:
        context.append("Role: " + roles.get(role_id, role_id))
    if channel_id:
        context.append("Channel: #" + channels.get(channel_id, channel_id))
    target = finding.get("target", "")
    if target.startswith("expect:"):
        context.append("Expectation: " + target[7:])
    body = "".join(
        f'<p>{_e(f["details"])}</p>'
        f'<p class="recommendation"><strong>Next step</strong>{_e(f["recommendation"])}</p>'
        for f in source
    )
    if mark:
        expired = state == "expired"
        body += (
            f'<p class="accepted-note{" expired" if expired else ""}"><strong>'
            f'{"Acceptance expired" if expired else "Accepted risk"} · until {_e(mark["expires"])}</strong>'
            f'{_e(mark["reason"])}'
            f'{" This finding counts as open again." if expired else ""}</p>')
    if item.get("note"):
        body += f'<p class="note">{_e(item["note"])}</p>'
    info = RULE_INFO.get(finding["code"])
    if info:
        body += f'<a class="rule-link" href="{_e(rule_url(finding["code"]))}" target="_blank" rel="noopener noreferrer">Rule reference{_icon("external")}</a>'
        if info["fixable"]:
            body += (f'<p class="note">Guided repair can revoke this with a reviewed plan: '
                     f'<code>python serversentry.py suggest YOUR_AUDIT.json --output policy.suggested.json</code> '
                     f'· {_link("Guided repairs", DOCS_URL + "repairs.md")}</p>')
    if item["before"] and item["after"]:
        body += (
            '<details class="evidence"><summary>Before / after evidence</summary><div class="pair">'
            f'<div><h4>Before</h4><pre>{_json(item["before"])}</pre></div>'
            f'<div><h4>After</h4><pre>{_json(item["after"])}</pre></div></div></details>'
        )
    badges = f'<span class="badge {_e(severity)}">{_icon(severity if severity in _ICONS else "info")}{_e(severity.capitalize())}</span>'
    if comparing:
        badges += f'<span class="status">{_e(STATUS_LABELS.get(status, status))}</span>'
    if state == "accepted":
        badges += f'<span class="badge accepted">{_icon("check")}Accepted</span>'
    elif state == "expired":
        badges += f'<span class="badge expired">{_icon("clock")}Acceptance expired</span>'
    icon = severity if severity in _ICONS else "info"
    return (
        f'<article class="finding {_e(severity)}" data-severity="{_e(severity)}" data-status="{_e(status)}" '
        f'data-rule="{_e(finding["code"])}" data-role="{_e(role_id)}" data-channel="{_e(channel_id)}" data-state="{state}">'
        f'<details><summary><span class="sev-icon">{_icon(icon)}</span><span class="finding-main">'
        f'<span class="badges">{badges}</span><strong class="finding-title">{_e(finding["title"])}</strong>'
        f'<span class="context">{"".join(f"<span>{_e(c)}</span>" for c in context) or "<span>Server-wide review</span>"}</span></span>'
        f'<span class="finding-meta"><code>{_e(finding["code"])}</code>{_icon("chevron", "chev")}</span></summary>'
        f'<div class="finding-body">{body}</div></details></article>'
    )


def _command(text: str) -> str:
    return (f'<div class="cmd"><code>{_e(text)}</code><button type="button" class="btn small" data-copy="{_e(text)}">'
            f'{_icon("copy")}<span class="copy-label">Copy</span></button></div>')


def _next_steps() -> str:
    steps = (
        ("Choose what to fix", "Pick findings and exactly which permissions to revoke. Works offline on this audit.",
         "python serversentry.py suggest YOUR_AUDIT.json --output policy.suggested.json", "Guided repairs", "repairs.md"),
        ("Preview the repair", "The fixer re-reads live data, shows each change and needs a typed confirmation.",
         "python discord_fix.py --policy policy.json", "Policy recipes", "policy-recipes.md"),
        ("Verify afterwards", "Run a new audit and compare it with this one. Missing data is never counted as fixed.",
         "python serversentry.py compare BEFORE.json AFTER.json --output comparison.html", "Reports & history", "reports.md"),
    )
    cards = "".join(
        f'<div class="card step"><h3>{_e(title)}</h3><p>{_e(text)}</p>{_command(command)}'
        f'<p>{_link(label + " →", DOCS_URL + doc, "external")}</p></div>'
        for title, text, command, label, doc in steps)
    return (
        '<section id="next"><div class="section-head"><div><p class="eyebrow">Act on it</p><h2>Next steps</h2></div></div>'
        '<p class="sub">ServerSentry never changes your server on its own. These commands run on your machine, '
        f'and every change is previewed first.</p><div class="steps">{cards}</div></section>')


def _policy_section(snapshot: dict) -> str:
    policy = snapshot.get("policy")
    if not policy:
        return ""
    findings = snapshot["findings"]
    violated = sum(f["code"] == "expectation_violated" for f in findings)
    unverifiable = sum(f["code"] == "expectation_unverifiable" for f in findings)

    def entries(rows: list[dict]) -> str:
        return "".join(
            f'<li><code>{_e(r["code"])}</code> · until {_e(r["expires"])} — {_e(r["reason"])}'
            + (f' (channel {_e(r["channel_id"])})' if r.get("channel_id") else "")
            + (f' (role {_e(r["role_id"])})' if r.get("role_id") else "") + "</li>" for r in rows)
    cards = (
        '<div class="card policy-card"><h3>' + _icon("shield") + 'Declared expectations</h3>'
        f'<p><strong>{policy["expectations_evaluated"]}</strong> evaluated · <strong>{violated}</strong> violated · '
        f'<strong>{unverifiable}</strong> cannot be verified</p>'
        '<p class="muted">Expectations state your intent. Names are never guessed.</p></div>'
        '<div class="card policy-card"><h3>' + _icon("check") + 'Accepted risks</h3>'
        f'<p><strong>{policy["accepted_count"]}</strong> active as of {_e(policy["as_of"])}</p>'
        '<p class="muted">Accepted findings stay in the data and reopen when the date passes.</p></div>'
    )
    if policy.get("expired"):
        cards += ('<div class="card policy-card alert"><h3>' + _icon("clock") + 'Expired acceptances (open again)</h3><ul>'
                  + entries(policy["expired"]) + "</ul></div>")
    if policy.get("expiring_soon"):
        cards += ('<div class="card policy-card"><h3>' + _icon("clock") + 'Expiring within 30 days</h3><ul>'
                  + entries(policy["expiring_soon"]) + "</ul></div>")
    if policy.get("unused_acceptances"):
        cards += ('<div class="card policy-card"><h3>' + _icon("info") + 'Acceptances that matched nothing</h3><ul>'
                  + entries(policy["unused_acceptances"]) + '</ul><p class="muted">Remove entries that are no longer needed.</p></div>')
    return (
        '<section id="policy"><div class="section-head"><div><p class="eyebrow">Your intent</p>'
        '<h2>Expectations &amp; accepted risks</h2></div>'
        f'<p>{_link("How it works", DOCS_URL + "expectations.md")}</p></div><div class="policy-grid">{cards}</div></section>')


def _footer(snapshot: dict) -> str:
    def column(title: str, links) -> str:
        return f'<div><h3>{_e(title)}</h3><ul>' + "".join(f"<li>{_link(label, url)}</li>" for label, url in links) + "</ul></div>"
    project = list(PROJECT_LINKS)
    if COMMUNITY_URL:
        project.insert(1, ("Community server", COMMUNITY_URL))
    audit = snapshot["audit"]
    privacy = ('<div><h3>Privacy</h3><ul><li><span class="muted">No telemetry, no external requests</span></li>'
               '<li><span class="muted">No message content collected</span></li>'
               '<li><span class="muted">Contains private server data</span></li></ul></div>')
    return (
        '<footer><div class="wrap"><div class="foot"><div><a class="brand" href="#overview">'
        f'{_icon("shield")}<span>ServerSentry</span></a>'
        '<p>Self-hosted permission auditor for Discord servers. It reads permissions, never messages, and runs only when you start it.</p></div>'
        + column("Project", project) + column("Documentation", DOC_LINKS) + privacy + '</div>'
        f'<div class="fineprint"><span>ServerSentry {_e(audit.get("tool_version", "legacy export"))} · ruleset {_e(audit.get("ruleset_version", "unknown"))}</span>'
        f'<span>Generated {_e(_when(audit["generated_at_utc"]))} · PolyForm Noncommercial 1.0.0</span></div></div></footer>')


def render_html(snapshot: dict, comparison: dict | None = None, baseline: dict | None = None) -> str:
    validate_snapshot(snapshot)
    roles = {r["id"]: r.get("name", r["id"]) for r in snapshot["roles"]}
    channels = {c["id"]: c.get("name", "Hidden channel") for c in snapshot["channels"]}
    if baseline:
        roles = {**{r["id"]: r.get("name", r["id"]) for r in baseline["roles"]}, **roles}
        channels = {**{c["id"]: c.get("name", "Hidden channel") for c in baseline["channels"]}, **channels}
    comparing = comparison is not None
    if comparison is None:
        items = [{"before": [], "after": [f], "severity_after": f["severity"], "status": "reported",
                  "role_id": f.get("role_id", ""), "channel_id": f.get("channel_id", "")}
                 for f in snapshot["findings"]]
    else:
        items = comparison["findings"]
    open_findings = [f for f in snapshot["findings"] if not f.get("accepted")]
    counts = Counter(f["severity"] for f in open_findings)
    accepted_total = len(snapshot["findings"]) - len(open_findings)
    total_open = len(open_findings)
    hidden = sum(bool(c.get("obfuscated")) for c in snapshot["channels"])
    limits = list(snapshot["audit"].get("limitations", []))
    limits += comparison["limitations"] if comparison else [
        "Risk signals require review. No findings does not establish that the server is secure.",
        "Only the recorded channel inventory is inspected. Missing or hidden areas are not verified.",
    ]
    limit_list = "".join(f"<li>{_e(x)}</li>" for x in dict.fromkeys(limits))
    cards = "".join(_finding_card(x, roles, channels, comparing) for x in items)
    sources = [f for item in items for f in (item["after"] or item["before"])]
    rule_options = _options({f["code"]: f["code"] for f in sources})
    status_options = _options({x["status"]: STATUS_LABELS.get(x["status"], x["status"].capitalize()) for x in items})
    finding_roles = {rid: roles.get(rid, rid) for x in items if (rid := _role_for(x, roles))}
    finding_channels = {x["channel_id"]: channels.get(x["channel_id"], x["channel_id"]) for x in items if x.get("channel_id")}
    item_counts = Counter(x.get("severity_after") or x.get("severity_before") or (x["after"] or x["before"])[0]["severity"] for x in items)
    server = snapshot["server"]
    audit = snapshot["audit"]
    heading = "Permission changes" if comparing else "Permission review"

    # ---- Overview ----
    segments = "".join(
        f'<span class="s-{name}" style="flex-grow:{counts[name]}"></span>' for name in ("critical", "warning", "info") if counts[name])
    summary_label = ", ".join(f"{counts[n]} {n}" for n in ("critical", "warning", "info") if counts[n]) or "no open findings"
    legend = "".join(
        f'<span><i style="background:var(--{name})"></i><strong>{counts[name]}</strong> {label}</span>'
        for name, label in (("critical", "critical"), ("warning", "warnings"), ("info", "info")))
    accepted_stat = (
        f'<div class="card stat accepted"><span class="label">{_icon("check")}Accepted risks</span>'
        f'<strong>{accepted_total}</strong><small>Reviewed and time-limited</small></div>') if snapshot.get("policy") else ""
    overview = (
        '<div class="overview"><div class="card posture"><h2>Open risk signals in this scan</h2>'
        f'<div class="total"><strong>{total_open}</strong><span>{"need review" if total_open else "found by automated checks"}</span></div>'
        f'<div class="bar-block"><div class="sevbar" role="img" aria-label="{_e(summary_label)}">{segments}</div><div class="legend">{legend}</div></div></div>'
        '<div class="stats">'
        f'<div class="card stat critical"><span class="label">{_icon("critical")}Critical</span><strong>{counts["critical"]}</strong><small>Review first</small></div>'
        f'<div class="card stat warning"><span class="label">{_icon("warning")}Warnings</span><strong>{counts["warning"]}</strong><small>Check server intent</small></div>'
        f'<div class="card stat info"><span class="label">{_icon("info")}Information</span><strong>{counts["info"]}</strong><small>Configuration context</small></div>'
        f'<div class="card stat hidden-ch"><span class="label">{_icon("eye-off")}Hidden channels</span><strong>{hidden}</strong><small>Not fully inspected</small></div>'
        f'{accepted_stat}</div></div>'
        f'<div class="notice">{_icon("info")}<p><strong>Evidence has limits.</strong> This report covers the recorded data; '
        'it does not certify that the server is secure. <a href="#scope">Read the scope</a></p></div>')

    # ---- Comparison header ----
    comparison_info = ""
    if comparing:
        chips = "".join(
            f'<button type="button" data-status="{_e(status)}" aria-pressed="false"><strong>{count}</strong>{_e(STATUS_LABELS.get(status, status))}</button>'
            for status, count in comparison["summary"].items())
        comparison_info = (
            '<div class="timeline"><div><span>Baseline</span>'
            f'<strong>{_e(_when(comparison["before"]["generated_at_utc"]))}</strong></div>'
            '<div class="arrow" aria-hidden="true">→</div><div><span>Current scan</span>'
            f'<strong>{_e(_when(comparison["after"]["generated_at_utc"]))}</strong></div></div>'
            f'<div class="comparison-counts" role="group" aria-label="Filter findings by change">{chips}</div>')

    # ---- Findings ----
    def seg(value: str, label: str, number: int, icon: str = "") -> str:
        return (f'<button type="button" data-value="{value}" aria-pressed="{"true" if not value else "false"}">'
                f'{_icon(icon) if icon else ""}{label}<span class="n">{number}</span></button>')
    severity_filter = (
        '<div class="seg" id="severity-filter" role="group" aria-label="Filter by severity">'
        + seg("", "All", len(items)) + seg("critical", "Critical", item_counts["critical"], "critical")
        + seg("warning", "Warning", item_counts["warning"], "warning") + seg("info", "Info", item_counts["info"], "info") + "</div>")
    state_options = "".join(f'<option value="{k}">{_e(v)}</option>' for k, v in STATE_LABELS.items())
    status_select = (f'<label>Change<select id="status"><option value="">All changes</option>{status_options}</select></label>'
                     if comparing else "")
    empty_text = ("No automated findings. Review the scope before drawing conclusions." if not items
                  else "No findings match these filters. Try a broader search or reset the filters.")
    findings = (
        '<section id="findings"><div class="section-head"><div><p class="eyebrow">Review queue</p>'
        f'<h2>Findings <span class="count">{len(items)}</span></h2></div></div>'
        '<noscript><p class="notice warn">Enable JavaScript to filter this report. All findings and evidence remain readable below.</p></noscript>'
        '<div class="card toolbar"><div class="toolbar-row">'
        f'<label class="search"><span class="sr-only">Search findings</span>{_icon("search")}'
        '<input id="search" type="search" placeholder="Search titles, evidence or permissions  ( / )" autocomplete="off"></label>'
        f'{severity_filter}</div>'
        '<details class="more"><summary>More filters' + _icon("chevron") + '</summary><div class="selects">'
        f'{status_select}<label>Review state<select id="state"><option value="">All states</option>{state_options}</select></label>'
        f'<label>Rule<select id="rule"><option value="">All rules</option>{rule_options}</select></label>'
        f'<label>Role<select id="role"><option value="">All roles</option>{_options(finding_roles)}</select></label>'
        f'<label>Channel<select id="channel"><option value="">All channels</option>{_options(finding_channels)}</select></label>'
        '</div></details></div>'
        f'<div class="statusline"><p id="result-count" role="status">{len(items)} of {len(items)} findings</p>'
        '<div class="toolbar-row"><button id="toggle-all" type="button" class="btn small ghost" aria-expanded="false">'
        f'{_icon("chevron")}<span class="copy-label">Expand all</span></button>'
        '<button id="reset" type="button" class="btn small">Reset filters</button></div></div>'
        f'<div id="finding-list">{cards}</div>'
        f'<p id="no-results" class="empty"{" hidden" if items else ""}>{_e(empty_text)}</p></section>')

    # ---- Object changes ----
    changes_html = ""
    if comparing:
        changes = []
        for change in comparison["changes"]:
            label = {"removed_or_unavailable": "Removed or unavailable", "not_comparable": "Coverage not comparable"}.get(
                change["status"], change["status"].capitalize())
            if change["kind"] == "channel" and change["status"] == "added":
                label = "Newly recorded"
            changes.append(
                '<details class="change"><summary>'
                f'<span class="badge neutral">{_e(label)}</span>'
                f'<strong>{_e(change["kind"].capitalize())}: {_e(change["name"])}</strong>'
                f'<span class="context">{_e(", ".join(change["fields"]))}</span></summary>'
                f'<p class="muted">ID: <code>{_e(change["id"])}</code></p><div class="pair">'
                f'<div><h4>Before</h4><pre>{_json(change["before"])}</pre></div>'
                f'<div><h4>After</h4><pre>{_json(change["after"])}</pre></div></div></details>')
        changes_html = (
            '<section id="changes"><div class="section-head"><div><p class="eyebrow">Configuration</p>'
            f'<h2>Object changes <span class="count">{len(changes)}</span></h2></div></div>'
            '<p class="sub">Before / after values for changed fields. Missing channels may be deleted or unavailable. '
            'Member overwrite patterns are aggregate counts, not member identity comparisons.</p>'
            '<label class="change-search">Search changes<input id="change-search" type="search" placeholder="Role, channel or permission"></label>'
            '<p id="change-count" role="status"></p>'
            + ("".join(changes) or '<p class="empty">No object changes in the comparable recorded data.</p>')
            + '<p id="changes-empty" class="empty" hidden>No changes match your search.</p></section>')

    # ---- Inventory ----
    inventory = ""
    for collection in ("roles", "channels"):
        rows = []
        for obj in snapshot[collection]:
            title = obj.get("name", "Hidden channel")
            if collection == "roles":
                detail = ", ".join(obj.get("guild_permissions", [])) or "No enabled server-wide permissions"
            else:
                detail = "Not fully inspected" if obj.get("obfuscated") else (
                    f'{obj.get("type", "channel")} · category sync: {obj.get("permissions_synced", "n/a")}')
            rows.append(f'<tr><th scope="row">{_e(title)}</th><td><code>{_e(obj["id"])}</code></td><td>{_e(detail)}</td></tr>')
        inventory += (
            f'<details class="card inventory"><summary>{collection.capitalize()} · {len(rows)}</summary>'
            '<div class="table-scroll"><table><thead><tr><th>Name</th><th>ID</th><th>Recorded permissions / coverage</th></tr></thead>'
            '<tbody>' + "".join(rows) + '</tbody></table></div></details>')

    assets = Path(__file__).resolve().parent / "assets"
    css = (assets / "report.css").read_text(encoding="utf-8")
    script = (assets / "report.js").read_text(encoding="utf-8")
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode("ascii")
    chips = (
        f'<span class="chip">{_icon("shield")}Read-only audit</span>'
        f'<span class="chip">Server <code>{_e(server["id"])}</code></span>'
        f'<span class="chip">{len(snapshot["roles"])} roles</span>'
        f'<span class="chip">{len(snapshot["channels"])} recorded channels</span>'
        f'<span class="chip">{_icon("clock")}{_e(_when(audit["generated_at_utc"]))}</span>')
    lead = ("What changed since the previous scan, and which risk signals remain."
            if comparing else "Understand the permissions. Review the evidence. Decide what needs attention.")
    nav = ('<a href="#overview">Overview</a><a href="#next">Next steps</a><a href="#findings">Findings</a>'
           + ('<a href="#changes">Changes</a>' if comparing else "")
           + ('<a href="#policy">Policy</a>' if snapshot.get("policy") else "")
           + '<a href="#inventory">Inventory</a><a href="#scope">Scope</a>')
    return f'''<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light"><meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>ServerSentry · {_e(server["name"])}</title><style>{css}</style><script>{script}</script></head>
<body>{_SPRITE}<a class="skip" href="#main">Skip to report</a>
<header class="topbar"><div class="wrap"><a class="brand" href="#overview">{_icon("shield")}<span>ServerSentry<small>Permission audit</small></span></a>
<nav class="topnav" aria-label="Report sections">{nav}</nav>
<div class="top-actions"><a class="btn ghost" href="{_e(REPO_URL)}" target="_blank" rel="noopener noreferrer">{_icon("github")}<span class="label">GitHub</span></a>
<a class="btn ghost" href="{_e(DOCS_URL)}reports.md" target="_blank" rel="noopener noreferrer">{_icon("book")}<span class="label">Docs</span></a>
<button id="theme-toggle" type="button" class="btn ghost icon-only theme-toggle" aria-label="Switch theme" hidden>{_icon("sun", "sun")}{_icon("moon", "moon")}</button></div></div></header>
<main id="main" class="wrap"><header id="overview" class="hero"><p class="eyebrow">{heading}</p><h1>{_e(server["name"])}</h1>
<p class="lead">{lead}</p><div class="chips">{chips}</div>{comparison_info}</header>
{overview}
{_next_steps()}
{findings}
{changes_html}
{_policy_section(snapshot)}
<section id="inventory"><div class="section-head"><div><p class="eyebrow">Recorded scope</p><h2>Server inventory</h2></div></div>
<p class="sub">Server-wide role permissions are not the same as a member’s effective channel permissions.</p>{inventory}</section>
<section id="scope" class="scope"><div class="section-head"><div><p class="eyebrow">Before drawing conclusions</p><h2>Scope &amp; limits</h2></div></div>
<div class="scope-grid"><div class="card" style="padding:20px"><ul>{limit_list}</ul></div>
<div class="card" style="padding:20px"><dl><div><dt>Generated at (UTC)</dt><dd>{_e(audit["generated_at_utc"])}</dd></div>
<div><dt>Scan</dt><dd>{_e(audit.get("scan_id", "Legacy export – not recorded"))}</dd></div>
<div><dt>Ruleset</dt><dd>{_e(audit.get("ruleset_version", "Legacy export – coverage unknown"))}</dd></div></dl></div></div></section></main>
{_footer(snapshot)}</body></html>'''
