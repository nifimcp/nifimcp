"""A03: malformed, duplicate-ID, oversized and deeply nested inputs rejected without data loss."""
import json

import pytest

from helpers import definition, group, processor, raw, sha, write_bundle
from nifimcp.core.flowmodel import FlowImportError, normalize
from nifimcp.core.jsonsafe import UnsafeJSON, loads_bounded
from nifimcp.errors import NiFiMCPError
from nifimcp.bundle.importer import import_bundle


def test_malformed_json_rejected():
    for bad in (b"{", b"{\"a\":1,}", b"\xff\xfe", b"[NaN]", b"{\"a\": Infinity}"):
        with pytest.raises(UnsafeJSON):
            loads_bounded(bad, max_bytes=1000)


def test_duplicate_json_keys_rejected():
    with pytest.raises(UnsafeJSON):
        loads_bounded(b'{"identifier":"a","identifier":"b"}', max_bytes=1000)


def test_oversized_input_rejected():
    with pytest.raises(UnsafeJSON):
        loads_bounded(b" " * 2000 + b"{}", max_bytes=1000)


def test_deep_json_nesting_rejected():
    data = b"[" * 200 + b"]" * 200
    with pytest.raises(UnsafeJSON):
        loads_bounded(data, max_bytes=10_000)


def test_duplicate_component_ids_rejected():
    root = group("root", processors=[processor("p1"), processor("p1")])
    with pytest.raises(FlowImportError):
        normalize(definition(root), source_id="t", source_hash="0" * 64)


def test_duplicate_instance_ids_rejected():
    a, b = processor("p1"), processor("p2")
    b["instanceIdentifier"] = a["instanceIdentifier"]
    with pytest.raises(FlowImportError):
        normalize(definition(group("root", processors=[a, b])), source_id="t", source_hash="0" * 64)


def test_deep_group_nesting_rejected():
    node = group("g40")
    for i in range(39, -1, -1):
        node = group(f"g{i}", processGroups=[node])
    with pytest.raises(FlowImportError):
        normalize(definition(node), source_id="t", source_hash="0" * 64)


def test_component_limit_rejected():
    root = group("root", processors=[processor(f"p{i}") for i in range(30)])
    with pytest.raises(FlowImportError):
        normalize(definition(root), source_id="t", source_hash="0" * 64, max_components=20)


def test_wrong_shapes_rejected():
    for doc in ({}, [], {"flowContents": {"identifier": "r", "processors": {}}},
                {"flowContents": {"identifier": "r", "processors": ["x"]}},
                {"flowContents": {"processors": [{"name": "no id"}]}}):
        with pytest.raises(FlowImportError):
            normalize(doc, source_id="t", source_hash="0" * 64)


def test_rejection_leaves_input_unchanged(tmp_path):
    root = group("root", processors=[processor("p1"), processor("p1")])
    folder = write_bundle(tmp_path / "b", definition(root))
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    bundle = import_bundle(folder, max_expanded_bytes=10_000_000)
    from nifimcp.sources import load_scope
    with pytest.raises(NiFiMCPError) as err:
        load_scope(bundle, max_components=100)
    assert err.value.code == "INVALID_BUNDLE"
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_error_messages_do_not_echo_content():
    secret = "DEMO-CANARY-IN-ERROR-0009"
    with pytest.raises(UnsafeJSON) as err:
        loads_bounded(('{"a":"' + secret + '",}').encode(), max_bytes=1000)
    assert secret not in str(err.value)
    with pytest.raises(FlowImportError) as err2:
        normalize({"flowContents": {"processors": [{"name": secret}]}}, source_id="t", source_hash="0" * 64)
    assert secret not in str(err2.value)
