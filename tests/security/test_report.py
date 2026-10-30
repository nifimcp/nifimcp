"""A15: hostile names, URLs and bulletins remain inert in portable reports."""
import re

from helpers import bundle_session, connection, definition, group, processor, run, write_bundle

HOSTILE = [
    "<script>alert('x')</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "</style><style>body{display:none}</style>",
    "<a href=\"https://evil.invalid/steal\">click</a>",
    "{{constructor.constructor('alert(1)')()}}",
    "<svg onload=alert(1)>",
    "<iframe src=//evil.invalid>",
]


def build(tmp_path):
    procs = [processor(f"p{i}", name, properties={"Remote URL": "https://evil.invalid/" + name, "note": name})
             for i, name in enumerate(HOSTILE)]
    conns = [connection("c0", "p0", "p1", rels=("unmatched",), name=HOSTILE[1])]
    root = group("root", HOSTILE[0], processors=procs, connections=conns)
    bulletins = {"collection": {}, "response": {"bulletinBoard": {"bulletins": [
        {"canRead": True, "bulletin": {"sourceId": procs[0]["instanceIdentifier"], "groupId": root["instanceIdentifier"],
                                       "sourceName": HOSTILE[2], "level": "ERROR", "message": HOSTILE[i % len(HOSTILE)],
                                       "timestampIso": "2026-10-29T01:30:00.000Z"}} for i in range(len(HOSTILE))]}}}
    status = {"collection": {}, "response": {"processGroupStatus": {"aggregateSnapshot": {
        "id": root["instanceIdentifier"], "processorStatusSnapshots": [{"processorStatusSnapshot": {
            "id": procs[1]["instanceIdentifier"], "name": HOSTILE[4], "runStatus": "Invalid"}}]}}}}
    window = {"start": "2026-10-29T01:00:00Z", "end": "2026-10-29T02:00:00Z"}
    folder = write_bundle(tmp_path / "b", definition(root), extra_files={
        "bulletins.json": ("bulletins", bulletins, None), "status.json": ("status", status, None)})
    svc = bundle_session(tmp_path, folder)
    d = run(svc, "describe_flow", {"scope_id": "test-scope"})
    run(svc, "get_flow_health", {"scope_id": "test-scope", "interval": window})
    exp = run(svc, "export_investigation", {"investigation_id": d["data"]["investigation_id"], "format": "html"})
    _, data = svc.s.store.read_bytes(exp["data"]["artifact"]["artifact_id"], svc.s.session_id)
    return data.decode()


def test_report_is_inert(tmp_path):
    html = build(tmp_path)
    lower = html.lower()
    for bad in ("<script", "<iframe", "<img", "<svg onload", "<a href=\"https"):
        assert bad not in lower, bad
    for tag in re.findall(r"<[a-zA-Z][^>]*>", html):
        attrs = re.findall(r"\s([a-zA-Z_:-]+)=", tag)
        assert not any(a.lower().startswith("on") for a in attrs), tag
    hrefs = re.findall(r'href="([^"]*)"', html)
    assert hrefs and all(h.startswith("#") for h in hrefs)
    assert re.findall(r'\ssrc="([^"]*)"', html) == []
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    # hostile text is present only in escaped form
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in html
    assert "&lt;/style&gt;&lt;style&gt;" in html


def test_no_active_or_remote_content(tmp_path):
    html = build(tmp_path)
    assert "@import" not in html
    assert re.findall(r"url\((?!#)", html) == []   # only internal SVG marker references
    assert not re.search(r"<(link|object|embed|form|base|meta http-equiv=\"refresh\")", html, re.I)


def test_svg_titles_escaped(tmp_path):
    html = build(tmp_path)
    svg = html[html.find("<svg"):html.find("</svg>")]
    assert "<script" not in svg and "onload=" not in svg.replace("onload=alert(1)&gt;", "")
