"""Investigation documents and self-contained, inert HTML reports.

The HTML has no scripts, no remote assets and a restrictive Content-Security-Policy.
Every dynamic string is escaped. Links are internal anchors only. A reader can move
from any finding to the exact sanitized evidence it cites.
"""
from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from typing import Any

from ..util import canonical_hash, iso, utc_now

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")
KIND_LABEL = {"observed": "Observed in NiFi", "deterministic_rule": "Static rule",
              "hypothesis": "Server hypothesis", "operator_assertion": "Operator assertion"}
ANCHOR = re.compile(r"[^A-Za-z0-9_-]")


def build_investigation_document(inv, *, mode: str, server_version: str, redaction: dict) -> dict:
    evidence: dict[str, dict] = {}
    findings: dict[str, dict] = {}
    gaps: list[dict] = []
    entries, intervals, sources = [], [], {}
    graph, timelines, health, unmatched, diffs = None, [], [], [], []
    status = "ok"
    for entry in inv.entries:
        env = entry["envelope"]
        if env["status"] in ("partial", "error"):
            status = "partial"
        for rec in env["evidence"]:
            evidence.setdefault(rec["evidence_id"], rec)
            sources.setdefault(rec["source_id"], rec["source_hash"])
        for f in env["findings"]:
            findings.setdefault(f["finding_id"], {**f, "from_tool": entry["tool"]})
        for g in env["gaps"]:
            if g not in gaps:
                gaps.append(g)
        if "interval" in entry:
            intervals.append({"tool": entry["tool"], **entry["interval"]})
        entries.append({"tool": entry["tool"], "request_id": env["request_id"], "status": env["status"],
                        "collected_at": env["collected_at"], "source_version": env["source_version"],
                        "limits_applied": env["limits_applied"]})
        data = env.get("data") or {}
        if entry["tool"] == "describe_flow" and isinstance(data.get("graph"), dict):
            graph = {"graph": data["graph"], "root_group": data.get("root_group"), "counts": data.get("counts"),
                     "source": data.get("source")}
        elif entry["tool"] == "trace_feed":
            timelines.append({"selector": data.get("selector"), "timeline": data.get("timeline", []),
                              "lineage_edges": data.get("lineage_edges", [])})
        elif entry["tool"] == "get_flow_health":
            health.append({"status": data.get("status"), "bulletins": data.get("bulletins"),
                           "interval": data.get("interval")})
        elif entry["tool"] == "inspect_unmatched":
            unmatched.append({k: data.get(k) for k in ("routing", "queue_status", "unmatched_events", "queue_sample",
                                                       "interval")})
        elif entry["tool"] == "compare_flow_snapshots":
            diffs.append({k: data.get(k) for k in ("added", "removed", "changed", "layout_only_changes_ignored",
                                                   "snapshot_fields_changed", "notes")})
    if status == "partial" and not any(g["code"] == "PARTIAL_INVESTIGATION" for g in gaps):
        gaps.append({"code": "PARTIAL_INVESTIGATION",
                     "detail": "At least one collection in this investigation was partial or failed."})
    ev_list = sorted(evidence.values(), key=lambda e: e["evidence_id"])
    return {
        "document_schema": "nifimcp-investigation/1",
        "investigation_id": inv.investigation_id,
        "scope": inv.scope,
        "mode": mode,
        "server_version": server_version,
        "created_at": inv.created_at,
        "exported_at": iso(utc_now()),
        "status": status,
        "entries": entries,
        "queried_intervals": intervals,
        "raw_source_hashes": [{"source_id": k, "sha256": v} for k, v in sorted(sources.items())],
        "findings": sorted(findings.values(), key=lambda f: ({"error": 0, "warning": 1, "review": 2, "info": 3}[f["severity"]],
                                                             f["finding_id"])),
        "evidence": ev_list,
        "gaps": gaps,
        "flow_map": graph,
        "timelines": timelines,
        "health": health,
        "unmatched": unmatched,
        "diffs": diffs,
        "redaction_policy": redaction,
        "integrity": {
            "evidence_sha256": canonical_hash(ev_list),
            "findings_sha256": canonical_hash(sorted(findings.values(), key=lambda f: f["finding_id"])),
            "note": "Hashes detect byte changes against this document. They do not authenticate the author and do "
                    "not make the document tamper-proof.",
        },
        "interpretation": {
            "model_generated": "Not recorded. NiFiMCP embeds no model; any explanation written by an MCP host's model "
                               "lives in that host's transcript and is not part of this evidence.",
            "untested_claims": "Static findings and hypotheses are not runtime tests. Draft artifacts are untested "
                               "until the separate lab verification runs.",
        },
    }


# ----------------------------------------------------------------------------- html
def e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def anchor(evidence_id: str) -> str:
    return "ev-" + ANCHOR.sub("_", evidence_id)[:120]


def _facts(value: Any, depth: int = 0) -> str:
    if depth > 6:
        return "<em>…</em>"
    if isinstance(value, dict):
        if not value:
            return "<em>empty</em>"
        rows = "".join(f"<tr><th scope=row>{e(k)}</th><td>{_facts(v, depth + 1)}</td></tr>" for k, v in value.items())
        return f"<table class=facts>{rows}</table>"
    if isinstance(value, list):
        if not value:
            return "<em>none</em>"
        return "<ul>" + "".join(f"<li>{_facts(v, depth + 1)}</li>" for v in value[:200]) + "</ul>"
    return f"<code>{e(value)}</code>"


def _svg(flow_map: dict | None) -> str:
    if not flow_map:
        return "<p>No flow map was collected in this investigation.</p>"
    graph = flow_map["graph"]
    nodes = [n for n in graph["nodes"] if n["kind"] not in ("label",)]
    edges = [x for x in graph["edges"] if x["source_id"] and x["destination_id"]]
    ids = {n["id"] for n in nodes}
    incoming = defaultdict(list)
    for x in edges:
        if x["source_id"] in ids and x["destination_id"] in ids:
            incoming[x["destination_id"]].append(x["source_id"])
    rank: dict[str, int] = {}

    def depth_of(nid: str, trail: frozenset = frozenset()) -> int:
        if nid in rank:
            return rank[nid]
        if nid in trail:
            return 0
        parents = [p for p in incoming.get(nid, []) if p != nid]
        value = 0 if not parents else 1 + max(depth_of(p, trail | {nid}) for p in parents)
        rank[nid] = min(value, 40)
        return rank[nid]

    shown = [n for n in nodes if n["kind"] != "process_group"][:150]
    for n in shown:
        depth_of(n["id"])
    columns: dict[int, list[dict]] = defaultdict(list)
    for n in shown:
        columns[rank.get(n["id"], 0)].append(n)
    w, h, gx, gy = 190, 46, 60, 24
    pos = {}
    for col, items in columns.items():
        for row, n in enumerate(items):
            pos[n["id"]] = (20 + col * (w + gx), 20 + row * (h + gy))
    width = 40 + (max(columns) + 1 if columns else 1) * (w + gx)
    height = 40 + max((len(v) for v in columns.values()), default=1) * (h + gy)
    parts = [f'<svg role="img" aria-labelledby="map-title" viewBox="0 0 {width} {height}" width="{width}" '
             f'height="{height}" xmlns="http://www.w3.org/2000/svg"><title id="map-title">Flow map: '
             f'{len(shown)} components, {len(edges)} connections</title>'
             '<defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" '
             'orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#5b6b73"/></marker></defs>']
    for x in edges:
        if x["source_id"] in pos and x["destination_id"] in pos:
            (x1, y1), (x2, y2) = pos[x["source_id"]], pos[x["destination_id"]]
            unmatched = "unmatched" in (x.get("relationships") or [])
            parts.append(f'<line x1="{x1 + w}" y1="{y1 + h / 2}" x2="{x2}" y2="{y2 + h / 2}" '
                         f'class="{"edge unmatched" if unmatched else "edge"}" marker-end="url(#arrow)">'
                         f'<title>{e(", ".join(x.get("relationships") or []) or "port")}</title></line>')
    for n in shown:
        x0, y0 = pos[n["id"]]
        label = (n.get("name") or n.get("type") or n["kind"])[:26]
        sub = (n.get("type") or n["kind"].replace("_", " "))[:28]
        parts.append(f'<g class="node {e(n["kind"])}"><rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="6"/>'
                     f'<text x="{x0 + 8}" y="{y0 + 19}">{e(label)}</text>'
                     f'<text class="sub" x="{x0 + 8}" y="{y0 + 36}">{e(sub)}</text>'
                     f'<title>{e(n.get("name"))} ({e(n["id"])})</title></g>')
    parts.append("</svg>")
    return "".join(parts)


def render_html(doc: dict) -> str:
    ev_ids = {r["evidence_id"] for r in doc["evidence"]}
    counts = defaultdict(int)
    for f in doc["findings"]:
        counts[f["kind"]] += 1

    def ev_links(ids: list[str]) -> str:
        return " ".join(f'<a href="#{anchor(i)}">{e(i)}</a>' if i in ev_ids else f"<span>{e(i)} (not in report)</span>"
                        for i in ids)

    findings_html = "".join(
        f'<tr class="sev-{e(f["severity"])}"><td><span class="kind k-{e(f["kind"])}">{e(KIND_LABEL.get(f["kind"], f["kind"]))}'
        f'</span></td><td>{e(f["severity"])}</td><td>{e(f["statement"])}'
        + ("<ul class=lim>" + "".join(f"<li>{e(lim)}</li>" for lim in f["limitations"]) + "</ul>" if f["limitations"] else "")
        + f'</td><td class=evlinks>{ev_links(f["evidence_ids"])}</td></tr>'
        for f in doc["findings"])
    evidence_html = "".join(
        f'<article class=evidence id="{anchor(r["evidence_id"])}"><h3>{e(r["evidence_id"])} '
        f'<small>{e(r["kind"])}</small></h3><dl>'
        f'<dt>Source</dt><dd>{e(r["source_id"])}</dd><dt>Source SHA-256</dt><dd><code>{e(r["source_hash"])}</code></dd>'
        f'<dt>Pointer</dt><dd><code>{e(r["source_pointer"])}</code></dd>'
        f'<dt>Component</dt><dd>{e(r["component_id"])}</dd><dt>Node</dt><dd>{e(r["node_id"])}</dd>'
        f'<dt>Event time</dt><dd>{e(r["event_time"])}</dd><dt>Collected</dt><dd>{e(r["collected_at"])}</dd></dl>'
        f'<details><summary>Sanitized facts</summary>{_facts(r["facts"])}</details></article>'
        for r in doc["evidence"])
    gaps_html = "".join(f"<li><strong>{e(g['code'])}</strong>: {e(g['detail'])}</li>" for g in doc["gaps"]) or "<li>None recorded.</li>"
    intervals_html = "".join(f"<li>{e(i['tool'])}: {e(i.get('start'))} to {e(i.get('end'))}"
                             f"{' (default window)' if i.get('defaulted') else ''}</li>" for i in doc["queried_intervals"]) \
        or "<li>No time-bounded queries.</li>"
    entries_html = "".join(f"<tr><td>{e(x['tool'])}</td><td>{e(x['status'])}</td><td>{e(x['collected_at'])}</td>"
                           f"<td>{e(x['source_version'])}</td><td><code>{e(x['request_id'])}</code></td></tr>"
                           for x in doc["entries"])
    sources_html = "".join(f"<li>{e(s['source_id'])}: <code>{e(s['sha256'])}</code></li>" for s in doc["raw_source_hashes"])
    timeline_html = ""
    for t in doc["timelines"]:
        rows = "".join(f"<tr><td>{e(x['time'])}</td><td>{e(x['event_type'])}</td><td>{e(x.get('component_name'))}</td>"
                       f"<td>{e(x.get('relationship'))}</td><td><code>{e(x.get('flowfile_uuid'))}</code></td>"
                       f"<td>{e(x.get('transit_uri'))}</td><td><a href=\"#{anchor(x['evidence_id'])}\">evidence</a></td></tr>"
                       for x in t["timeline"])
        timeline_html += (f"<h3>Selector: {e(json.dumps(t['selector'], sort_keys=True))}</h3>"
                          f"<table><tr><th>Time</th><th>Event</th><th>Component</th><th>Relationship</th>"
                          f"<th>FlowFile</th><th>Transit URI</th><th></th></tr>{rows}</table>")
    flow_table = ""
    if doc["flow_map"]:
        flow_table = "".join(
            f"<tr><td>{e(n.get('name'))}</td><td>{e(n['kind'])}</td><td>{e(n.get('type'))}</td><td><code>{e(n['id'])}</code></td>"
            f"<td>{'<a href=\"#' + anchor(n['evidence_id']) + '\">evidence</a>' if n.get('evidence_id') in ev_ids else ''}</td></tr>"
            for n in doc["flow_map"]["graph"]["nodes"][:500])
    status_class = "partial" if doc["status"] == "partial" else "ok"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>NiFiMCP investigation {e(doc['investigation_id'])}</title>
<style>
:root{{--fg:#16232a;--muted:#55666e;--bg:#ffffff;--line:#d5dde1;--accent:#0b6e69;--warn:#9a5b00;--bad:#a1262b}}
body{{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0}}
main{{max-width:1180px;margin:auto;padding:24px 16px 64px}}
h1{{font-size:26px;margin:0 0 4px}} h2{{font-size:19px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:4px}}
h3{{font-size:15px;margin:16px 0 6px}} small{{color:var(--muted);font-weight:400}}
table{{border-collapse:collapse;width:100%;margin:8px 0}} th,td{{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}}
code{{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:600}} .badge.ok{{background:#e1f3ef;color:var(--accent)}}
.badge.partial{{background:#fff1dd;color:var(--warn)}} .kind{{font-size:12px;padding:1px 6px;border-radius:4px;background:#eef2f4;white-space:nowrap}}
.k-hypothesis{{background:#fff1dd}} .k-observed{{background:#e1f3ef}} .k-operator_assertion{{background:#efe7fb}}
.sev-warning td:nth-child(2),.sev-error td:nth-child(2){{color:var(--bad);font-weight:600}}
.lim{{color:var(--muted);font-size:13px;margin:4px 0 0;padding-left:18px}} .evlinks a{{display:block;font:12px ui-monospace,monospace}}
.evidence{{border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:10px 0}}
.evidence:target{{outline:3px solid var(--accent)}} dl{{display:grid;grid-template-columns:140px 1fr;gap:2px 12px;margin:6px 0}}
dt{{color:var(--muted)}} dd{{margin:0;overflow-wrap:anywhere}} .facts th{{width:220px;color:var(--muted);font-weight:500}}
.legend li{{margin:2px 0}} .scroll{{overflow-x:auto;border:1px solid var(--line);border-radius:6px}}
svg .node rect{{fill:#f4f8f9;stroke:#8aa0a8}} svg .node.input_port rect,svg .node.output_port rect{{fill:#e1f3ef}}
svg text{{font:12px system-ui,sans-serif;fill:#16232a}} svg text.sub{{fill:#55666e;font-size:11px}}
svg .edge{{stroke:#5b6b73;stroke-width:1.2}} svg .edge.unmatched{{stroke:#9a5b00;stroke-dasharray:5 3}}
summary{{cursor:pointer}} a{{color:var(--accent)}} a:focus,summary:focus{{outline:2px solid var(--accent)}}
@media print{{.scroll{{overflow:visible}} a{{color:inherit;text-decoration:none}} details{{display:block}} .evidence{{break-inside:avoid}}}}
</style></head><body><main>
<h1>NiFiMCP investigation report</h1>
<p><span class="badge {status_class}">{e(doc['status'].upper())}</span> &nbsp; scope <strong>{e(doc['scope'])}</strong> ·
mode {e(doc['mode'])} · investigation <code>{e(doc['investigation_id'])}</code> · server {e(doc['server_version'])} ·
exported {e(doc['exported_at'])}</p>
<p>Independent tooling for Apache NiFi. Not affiliated with or endorsed by the Apache Software Foundation.
All names, messages and notes below come from the inspected system and are untrusted text.</p>

<h2>How to read this report</h2>
<ul class=legend>
<li><span class="kind k-observed">Observed in NiFi</span> {counts['observed']} finding(s) taken from collected NiFi status, bulletins or provenance at the stated time.</li>
<li><span class="kind k-deterministic_rule">Static rule</span> {counts['deterministic_rule']} configuration review item(s) from fixed rules. They are review concerns, not measured incidents.</li>
<li><span class="kind k-hypothesis">Server hypothesis</span> {counts['hypothesis']} plausible explanation(s) produced by fixed rules. Unverified.</li>
<li><span class="kind k-operator_assertion">Operator assertion</span> {counts['operator_assertion']} note(s) written by people. They cannot override NiFi evidence.</li>
<li><strong>Model-generated interpretation:</strong> {e(doc['interpretation']['model_generated'])}</li>
<li><strong>Untested claims:</strong> {e(doc['interpretation']['untested_claims'])}</li>
</ul>

<h2>Collections</h2>
<table><tr><th>Tool</th><th>Status</th><th>Collected</th><th>Source version</th><th>Request</th></tr>{entries_html}</table>
<h3>Queried intervals</h3><ul>{intervals_html}</ul>

<h2>Flow map</h2>
<div class=scroll>{_svg(doc['flow_map'])}</div>
<details><summary>Component table (text alternative to the map)</summary>
<table><tr><th>Name</th><th>Kind</th><th>Type</th><th>ID</th><th></th></tr>{flow_table}</table></details>

<h2>Findings</h2>
<table><tr><th>Kind</th><th>Severity</th><th>Statement and limitations</th><th>Evidence</th></tr>{findings_html}</table>

<h2>Provenance timeline</h2>
{timeline_html or '<p>No provenance trace was collected in this investigation.</p>'}

<h2>Gaps, limits and omissions</h2>
<ul>{gaps_html}</ul>
<h3>Redaction policy</h3>{_facts(doc['redaction_policy'])}

<h2>Evidence</h2>
<p>Each record cites the exact source bytes (SHA-256) and a JSON pointer. A verified citation shows the reference
resolves; it does not show that reasoning drawn from it is correct.</p>
{evidence_html}

<h2>Integrity</h2>
<p>Evidence SHA-256 <code>{e(doc['integrity']['evidence_sha256'])}</code><br>
Findings SHA-256 <code>{e(doc['integrity']['findings_sha256'])}</code><br>{e(doc['integrity']['note'])}</p>
<h3>Raw input hashes</h3><ul>{sources_html or '<li>None.</li>'}</ul>
</main></body></html>
"""
