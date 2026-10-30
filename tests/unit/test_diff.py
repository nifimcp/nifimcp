"""A04: layout ignored; semantic list order and ID changes preserved; values never emitted."""
import json

from helpers import connection, definition, group, processor, raw, sha, deepcopy
from nifimcp.core.diff import diff_models
from nifimcp.core.flowmodel import normalize


def base():
    root = group("root", "Root", processors=[processor("a", properties={"endpoint": "https://x.invalid"}), processor("b")],
                 connections=[connection("c", "a", "b")])
    return definition(root)


def m(doc):
    data = raw(doc)
    return normalize(json.loads(data), source_id="t", source_hash=sha(data))


def test_layout_and_order_ignored():
    a, b = base(), base()
    b["flowContents"]["processors"].reverse()
    b["flowContents"]["processors"][0]["position"] = {"x": 900.0, "y": 10.0}
    b["flowContents"]["connections"][0]["bends"] = [{"x": 1, "y": 2}]
    result = diff_models(m(a), m(b))
    assert result["changed"] == [] and result["added"] == [] and result["removed"] == []
    assert result["layout_only_changes_ignored"] >= 1


def test_semantic_list_order_preserved():
    a, b = base(), base()
    a["flowContents"]["connections"][0]["prioritizers"] = ["x.First", "x.Second"]
    b["flowContents"]["connections"][0]["prioritizers"] = ["x.Second", "x.First"]
    result = diff_models(m(a), m(b))
    assert [c["changed_fields"] for c in result["changed"]] == [["/prioritizers"]]


def test_relationship_set_order_is_not_semantic():
    a, b = base(), base()
    a["flowContents"]["connections"][0]["selectedRelationships"] = ["success", "failure"]
    b["flowContents"]["connections"][0]["selectedRelationships"] = ["failure", "success"]
    assert diff_models(m(a), m(b))["changed"] == []


def test_identifier_change_is_visible_as_add_remove():
    a, b = base(), base()
    b["flowContents"]["processors"][1]["identifier"] = "b-regenerated"
    b["flowContents"]["connections"][0]["destination"]["id"] = "b-regenerated"
    result = diff_models(m(a), m(b))
    assert [x["identifier"] for x in result["added"]] == ["b-regenerated"]
    assert [x["identifier"] for x in result["removed"]] == ["b"]
    assert result["possible_regenerated_identifiers"] is True
    assert any(c["identifier"] == "c" for c in result["changed"])


def test_values_never_emitted():
    a, b = base(), base()
    b["flowContents"]["processors"][0]["properties"]["endpoint"] = "https://PRIVATE-HOST.invalid/secret"
    b["parameterContexts"] = {"secret": {"name": "secret", "parameters": [{"name": "k", "value": "PRIVATE-VALUE"}]}}
    result = diff_models(m(a), m(b))
    text = json.dumps(result)
    assert "PRIVATE-HOST" not in text and "PRIVATE-VALUE" not in text and "x.invalid" not in text
    assert result["changed"][0]["changed_fields"] == ["/properties/endpoint"]
    assert result["snapshot_fields_changed"] == ["parameterContexts"]
