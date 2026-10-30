"""Strict offline bundle import (zip or directory). Makes no network requests.

Rejected: absolute paths, parent traversal, backslashes, symlinks, duplicate
normalized names, unlisted entries, excessive compression ratios, oversized
expansion, unsupported schemas or versions, hash or size mismatches and JSON
that violates parsing bounds. Inputs are never modified.
"""
from __future__ import annotations

import os
import posixpath
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..core.jsonsafe import UnsafeJSON, loads_bounded
from ..errors import ErrorCode, NiFiMCPError
from ..limits import MAX_BUNDLE_COMPRESSION_RATIO, MAX_BUNDLE_FILES, MAX_SINGLE_JSON_BYTES
from ..util import sha256_hex
from .manifest import BundleManifest

MANIFEST = "manifest.json"
QUALIFIED_VERSIONS = {"2.12.0"}


def _fail(message: str) -> NiFiMCPError:
    return NiFiMCPError(ErrorCode.INVALID_BUNDLE, f"bundle rejected: {message}")


@dataclass
class BundleFileData:
    path: str
    kind: str
    raw: bytes
    sha256: str
    document: Any
    meta: Any


@dataclass
class ImportedBundle:
    manifest: BundleManifest
    manifest_sha256: str
    files: list[BundleFileData]
    gaps: list[dict] = field(default_factory=list)

    def of_kind(self, kind: str) -> list[BundleFileData]:
        return [f for f in self.files if f.kind == kind]


def _safe_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise _fail("entry name contains an invalid character")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise _fail("entry uses an absolute path")
    norm = posixpath.normpath(name)
    if norm.startswith("../") or norm == ".." or "/../" in f"/{norm}/":
        raise _fail("entry escapes the bundle root")
    if "/" in norm:
        raise _fail("nested directories are not allowed in a bundle")
    return norm


def _read_zip(path: Path, max_total: int) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise _fail("not a readable zip archive") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_BUNDLE_FILES + 1:
            raise _fail("too many entries")
        seen: dict[str, bytes] = {}
        lowered: set[str] = set()
        total = 0
        for info in infos:
            if info.is_dir():
                raise _fail("directories are not allowed in a bundle")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise _fail("symbolic links are not allowed")
            name = _safe_name(info.filename)
            if name.lower() in lowered:
                raise _fail("duplicate entry name")
            lowered.add(name.lower())
            if info.file_size > MAX_SINGLE_JSON_BYTES:
                raise _fail("an entry exceeds the per-file size limit")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_BUNDLE_COMPRESSION_RATIO:
                raise _fail("an entry exceeds the allowed compression ratio")
            total += info.file_size
            if total > max_total:
                raise _fail("expanded size exceeds the configured limit")
            with archive.open(info) as handle:
                data = handle.read(info.file_size + 1)
            if len(data) != info.file_size:
                raise _fail("entry size does not match its header")
            seen[name] = data
        return seen


def _read_dir(path: Path, max_total: int) -> dict[str, bytes]:
    if path.is_symlink():
        raise _fail("bundle directory is a symbolic link")
    entries = sorted(os.scandir(path), key=lambda e: e.name)
    if len(entries) > MAX_BUNDLE_FILES + 1:
        raise _fail("too many entries")
    seen: dict[str, bytes] = {}
    lowered: set[str] = set()
    total = 0
    for entry in entries:
        if entry.is_symlink():
            raise _fail("symbolic links are not allowed")
        if not entry.is_file(follow_symlinks=False):
            raise _fail("only regular files are allowed in a bundle directory")
        name = _safe_name(entry.name)
        if name.lower() in lowered:
            raise _fail("duplicate entry name")
        lowered.add(name.lower())
        size = entry.stat(follow_symlinks=False).st_size
        if size > MAX_SINGLE_JSON_BYTES:
            raise _fail("an entry exceeds the per-file size limit")
        total += size
        if total > max_total:
            raise _fail("expanded size exceeds the configured limit")
        fd = os.open(entry.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            seen[name] = handle.read(size + 1)
        if len(seen[name]) != size:
            raise _fail("file changed while reading")
    return seen


def import_bundle(path: str | os.PathLike, *, max_expanded_bytes: int) -> ImportedBundle:
    src = Path(path)
    try:
        if src.is_symlink():
            raise _fail("bundle path is a symbolic link")
        if src.is_dir():
            entries = _read_dir(src, max_expanded_bytes)
        elif src.is_file():
            entries = _read_zip(src, max_expanded_bytes)
        else:
            raise _fail("bundle path does not exist")
    except OSError as exc:
        raise _fail("bundle could not be read") from exc
    if MANIFEST not in entries:
        raise _fail("manifest.json is missing")
    manifest_raw = entries.pop(MANIFEST)
    try:
        manifest_doc = loads_bounded(manifest_raw, max_bytes=1024 * 1024, max_depth=16)
        manifest = BundleManifest.model_validate(manifest_doc)
    except UnsafeJSON as exc:
        raise _fail(f"manifest is not valid JSON ({exc})") from exc
    except ValidationError as exc:
        where = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})[:8]
        raise _fail("manifest failed schema validation at: " + (", ".join(where) or "root")) from exc
    major = int(manifest.nifi.version.split(".")[0])
    if major != 2:
        raise NiFiMCPError(ErrorCode.UNSUPPORTED_VERSION,
                           f"bundle was collected from NiFi {manifest.nifi.version}; only NiFi 2.x bundles are accepted")
    listed = {f.path for f in manifest.files}
    unlisted = sorted(set(entries) - listed)
    if unlisted:
        raise _fail(f"{len(unlisted)} file(s) are present but not listed in the manifest")
    missing = sorted(listed - set(entries))
    if missing:
        raise _fail(f"{len(missing)} listed file(s) are missing")
    files: list[BundleFileData] = []
    for meta in manifest.files:
        raw = entries[meta.path]
        if len(raw) != meta.bytes:
            raise _fail(f"size mismatch for {meta.path}")
        digest = sha256_hex(raw)
        if digest != meta.sha256:
            raise _fail(f"hash mismatch for {meta.path}")
        try:
            document = loads_bounded(raw, max_bytes=MAX_SINGLE_JSON_BYTES)
        except UnsafeJSON as exc:
            raise _fail(f"{meta.path} is not acceptable JSON ({exc})") from exc
        files.append(BundleFileData(path=meta.path, kind=meta.kind, raw=raw, sha256=digest, document=document, meta=meta))
    gaps = []
    if manifest.nifi.version not in QUALIFIED_VERSIONS:
        gaps.append({"code": "VERSION_NOT_QUALIFIED",
                     "detail": f"Bundle declares NiFi {manifest.nifi.version}; NiFiMCP is qualified on 2.12.0 only."})
    if manifest.completeness.status == "partial":
        gaps.append({"code": "BUNDLE_PARTIAL",
                     "detail": "Bundle declares partial completeness: " + "; ".join(manifest.completeness.missing)[:1500]})
    for node in manifest.nodes:
        if not node.included:
            gaps.append({"code": "NODE_NOT_INCLUDED", "detail": f"Node {node.node_id} is declared but not included."})
    if any(f.meta.origin == "human_transcribed" for f in files):
        gaps.append({"code": "HUMAN_TRANSCRIBED_INPUT",
                     "detail": "Some files are human-transcribed assertions, not machine-collected NiFi facts."})
    return ImportedBundle(manifest=manifest, manifest_sha256=sha256_hex(manifest_raw), files=files, gaps=gaps)
