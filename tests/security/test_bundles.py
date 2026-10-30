"""A14: traversal, symlink, duplicate, bomb, unlisted file and bad hashes rejected."""
import io
import json
import os
import stat
import zipfile

import pytest

from helpers import definition, group, processor, raw, sha, write_bundle
from nifimcp.bundle.importer import import_bundle
from nifimcp.errors import NiFiMCPError

LIMIT = 50 * 1024 * 1024


def good(tmp_path):
    return write_bundle(tmp_path / "bundle", definition(group("root", processors=[processor("p1")])))


def zip_from(folder, target, extra=None, rename=None):
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.iterdir()):
            z.write(p, (rename or {}).get(p.name, p.name))
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return target


def rejects(path, code="INVALID_BUNDLE"):
    with pytest.raises(NiFiMCPError) as err:
        import_bundle(path, max_expanded_bytes=LIMIT)
    assert err.value.code == code
    return err.value


def test_good_bundle_directory_and_zip(tmp_path):
    folder = good(tmp_path)
    assert import_bundle(folder, max_expanded_bytes=LIMIT).manifest.bundle_id == "test-bundle"
    assert import_bundle(zip_from(folder, tmp_path / "b.zip"), max_expanded_bytes=LIMIT).files


@pytest.mark.parametrize("name", ["../evil.json", "/abs.json", "sub/inner.json", "..\\win.json", "C:evil.json"])
def test_path_tricks_rejected(tmp_path, name):
    rejects(zip_from(good(tmp_path), tmp_path / "b.zip", extra={name: b"{}"}))


def test_zip_symlink_rejected(tmp_path):
    target = zip_from(good(tmp_path), tmp_path / "b.zip")
    with zipfile.ZipFile(target, "a") as z:
        info = zipfile.ZipInfo("link.json")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
    rejects(target)


def test_directory_symlink_rejected(tmp_path):
    folder = good(tmp_path)
    os.symlink("/etc/hostname", folder / "link.json")
    rejects(folder)


def test_bundle_path_symlink_rejected(tmp_path):
    folder = good(tmp_path)
    os.symlink(folder, tmp_path / "alias")
    rejects(tmp_path / "alias")


def test_duplicate_names_rejected(tmp_path):
    folder = good(tmp_path)
    target = tmp_path / "b.zip"
    with zipfile.ZipFile(target, "w") as z:
        for p in sorted(folder.iterdir()):
            z.write(p, p.name)
        z.writestr("FLOW-DEFINITION.json", b"{}")
    rejects(target)


def test_compression_bomb_rejected(tmp_path):
    folder = good(tmp_path)
    rejects(zip_from(folder, tmp_path / "b.zip", extra={"bomb.json": b"0" * (5 * 1024 * 1024)}))


def test_expanded_size_limit(tmp_path):
    folder = good(tmp_path)
    with pytest.raises(NiFiMCPError):
        import_bundle(folder, max_expanded_bytes=100)


def test_unlisted_file_rejected(tmp_path):
    folder = good(tmp_path)
    (folder / "extra.json").write_text("{}")
    rejects(folder)


def test_missing_listed_file_rejected(tmp_path):
    folder = good(tmp_path)
    (folder / "flow-definition.json").unlink()
    rejects(folder)


def test_hash_and_size_mismatch_rejected(tmp_path):
    folder = good(tmp_path)
    data = (folder / "flow-definition.json").read_bytes()
    (folder / "flow-definition.json").write_bytes(data.replace(b'"p"', b'"q"'))
    rejects(folder)
    (folder / "flow-definition.json").write_bytes(data + b" ")
    rejects(folder)


def test_unsupported_schema_and_versions(tmp_path):
    folder = good(tmp_path)
    m = json.loads((folder / "manifest.json").read_text())
    for patch, code in ((("bundle_schema", "nifimcp-bundle/2"), "INVALID_BUNDLE"),
                        (("nifi", {"version": "1.28.0", "profile": "x"}), "UNSUPPORTED_VERSION"),
                        (("unexpected", True), "INVALID_BUNDLE")):
        bad = dict(m)
        bad[patch[0]] = patch[1]
        (folder / "manifest.json").write_text(json.dumps(bad))
        rejects(folder, code)


def test_manifest_consistency_rules(tmp_path):
    folder = good(tmp_path)
    m = json.loads((folder / "manifest.json").read_text())
    bad = dict(m, nodes=[{"node_id": "standalone", "included": False}])
    (folder / "manifest.json").write_text(json.dumps(bad))
    rejects(folder)   # excluded node without partial completeness
    bad = dict(m, source_kinds=["flow_definition", "status"])
    (folder / "manifest.json").write_text(json.dumps(bad))
    rejects(folder)


def test_malformed_json_member_rejected(tmp_path):
    folder = good(tmp_path)
    m = json.loads((folder / "manifest.json").read_text())
    data = b'{"a":1,"a":2}'
    (folder / "flow-definition.json").write_bytes(data)
    m["files"][0].update(sha256=sha(data), bytes=len(data))
    (folder / "manifest.json").write_text(json.dumps(m))
    rejects(folder)


def test_partial_and_version_gaps(tmp_path):
    folder = write_bundle(tmp_path / "b", definition(group("root", processors=[processor("p1")])),
                          manifest_overrides={"nodes": [{"node_id": "standalone", "included": True},
                                                        {"node_id": "node-2", "included": False}],
                                              "completeness": {"status": "partial", "missing": ["node-2 offline"]},
                                              "nifi": {"version": "2.11.0", "profile": "stock"}})
    bundle = import_bundle(folder, max_expanded_bytes=LIMIT)
    codes = {g["code"] for g in bundle.gaps}
    assert {"BUNDLE_PARTIAL", "NODE_NOT_INCLUDED", "VERSION_NOT_QUALIFIED"} <= codes
