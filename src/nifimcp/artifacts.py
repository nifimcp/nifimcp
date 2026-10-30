"""Private artifact workspace.

* Directories are created 0700 and files 0600 inside the operator-configured
  artifact directory. No path ever comes from a tool argument.
* Operator registration (CLI only) copies validated inputs into the workspace
  and assigns ``art_`` IDs before an MCP session starts.
* Session artifacts (exports, drafts, oversized results) are owned by the session
  that created them. Other sessions cannot read them.
* Every read re-verifies the stored SHA-256; a changed file is STALE_ARTIFACT.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from .errors import ErrorCode, NiFiMCPError
from .limits import MAX_ARTIFACTS_PER_SESSION, MAX_RAW_OBSERVATIONS_PER_SESSION
from .util import iso, sha256_hex, utc_now

REGISTRY = "registry.json"
ARTIFACT_KINDS = {"bundle", "flow_definition", "investigation_json", "investigation_html", "draft",
                  "draft_receipt", "result", "lab_result", "raw_observation"}


def new_artifact_id() -> str:
    return "art_" + secrets.token_urlsafe(18)


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


@dataclass
class ArtifactRecord:
    artifact_id: str
    kind: str
    owner: str            # "operator" or a session id
    relpath: str          # relative to the artifact root
    sha256: str
    bytes: int
    created_at: str
    label: str = ""
    media_type: str = "application/json"
    scope: str | None = None

    def public(self) -> dict:
        return {"artifact_id": self.artifact_id, "kind": self.kind, "sha256": self.sha256, "bytes": self.bytes,
                "created_at": self.created_at, "label": self.label, "media_type": self.media_type,
                "scope": self.scope, "uri": f"nifimcp://artifacts/{self.artifact_id}",
                "owner": "operator" if self.owner == "operator" else "this session"}


class ArtifactStore:
    def __init__(self, root: Path, retention_days: int):
        self.root = _private_dir(Path(root))
        self.retention = dt.timedelta(days=retention_days)
        _private_dir(self.root / "registered")
        _private_dir(self.root / "sessions")
        self._records: dict[str, ArtifactRecord] = {}
        self._load_registry()

    # ---------------------------------------------------------- registry
    def _load_registry(self) -> None:
        path = self.root / REGISTRY
        if not path.is_file():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("artifacts", []):
            rec = ArtifactRecord(**item)
            if rec.owner == "operator":
                self._records[rec.artifact_id] = rec

    def _save_registry(self) -> None:
        items = [vars(r) for r in self._records.values() if r.owner == "operator"]
        _write_private(self.root / REGISTRY, (json.dumps({"artifacts": items}, indent=1, sort_keys=True) + "\n").encode())

    def register_operator_file(self, source: Path, kind: str, label: str = "", scope: str | None = None) -> ArtifactRecord:
        """Copy an operator-supplied, already-validated file or bundle directory into the workspace."""
        if kind not in ("bundle", "flow_definition"):
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "only bundles and flow definitions can be registered")
        aid = new_artifact_id()
        target = self.root / "registered" / aid
        if source.is_dir():
            _private_dir(target)
            digest_parts = []
            for entry in sorted(source.iterdir()):
                if entry.is_symlink() or not entry.is_file():
                    raise NiFiMCPError(ErrorCode.INVALID_BUNDLE, "bundle directory contains a non-regular file")
                data = entry.read_bytes()
                _write_private(target / entry.name, data)
                digest_parts.append(f"{entry.name}:{sha256_hex(data)}")
            sha = sha256_hex("\n".join(digest_parts).encode())
            size = sum(p.stat().st_size for p in target.iterdir())
            relpath = f"registered/{aid}"
        else:
            data = source.read_bytes()
            _private_dir(target)
            name = "bundle.zip" if kind == "bundle" else "flow.json"
            _write_private(target / name, data)
            sha, size, relpath = sha256_hex(data), len(data), f"registered/{aid}/{name}"
        rec = ArtifactRecord(artifact_id=aid, kind=kind, owner="operator", relpath=relpath, sha256=sha, bytes=size,
                             created_at=iso(utc_now()), label=label[:200], scope=scope)
        self._records[aid] = rec
        self._save_registry()
        return rec

    @staticmethod
    def digest_of(source: Path) -> str:
        """The digest register_operator_file would record for ``source``."""
        if source.is_dir():
            parts = [f"{e.name}:{sha256_hex(e.read_bytes())}" for e in sorted(source.iterdir()) if e.is_file()]
            return sha256_hex("\n".join(parts).encode())
        return sha256_hex(source.read_bytes())

    def operator_records(self, kind: str | None = None) -> list[ArtifactRecord]:
        return [r for r in self._records.values() if r.owner == "operator" and (kind is None or r.kind == kind)]

    def unregister(self, artifact_id: str) -> ArtifactRecord:
        """Remove an operator-registered input (its copy in the workspace and its registry entry)."""
        rec = self._records.get(artifact_id)
        if rec is None or rec.owner != "operator":
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "no registered input has that artifact ID",
                               "List registered inputs with `nifimcp capabilities --config <file>`.")
        self._drop(rec)
        self._save_registry()
        return rec

    def _drop(self, rec: ArtifactRecord) -> None:
        folder = (self.root / rec.relpath).resolve()
        if folder.is_file():
            folder = folder.parent
        if self.root.resolve() in folder.parents and folder.name == rec.artifact_id:
            shutil.rmtree(folder, ignore_errors=True)
        self._records.pop(rec.artifact_id, None)

    # ---------------------------------------------------------- session
    def session_dir(self, session_id: str) -> Path:
        return _private_dir(self.root / "sessions" / session_id)

    def put(self, session_id: str, kind: str, data: bytes, *, filename: str, media_type: str,
            label: str = "", scope: str | None = None) -> ArtifactRecord:
        if kind not in ARTIFACT_KINDS:
            raise ValueError("unknown artifact kind")
        if kind == "raw_observation":
            raws = sorted((r for r in self._records.values() if r.owner == session_id and r.kind == "raw_observation"),
                          key=lambda r: (r.created_at, r.artifact_id))
            for old in raws[:max(0, len(raws) - MAX_RAW_OBSERVATIONS_PER_SESSION + 1)]:
                self._drop(old)
        else:
            owned = [r for r in self._records.values() if r.owner == session_id and r.kind != "raw_observation"]
            if len(owned) >= MAX_ARTIFACTS_PER_SESSION:
                raise NiFiMCPError(ErrorCode.LIMIT_EXCEEDED, "this session reached its artifact limit",
                                   "Export what you need, then start a new MCP session (restart the server).")
        if "/" in filename or filename.startswith("."):
            raise ValueError("invalid artifact filename")
        aid = new_artifact_id()
        folder = _private_dir(self.session_dir(session_id) / aid)
        _write_private(folder / filename, data)
        rec = ArtifactRecord(artifact_id=aid, kind=kind, owner=session_id,
                             relpath=f"sessions/{session_id}/{aid}/{filename}", sha256=sha256_hex(data),
                             bytes=len(data), created_at=iso(utc_now()), label=label[:200],
                             media_type=media_type, scope=scope)
        self._records[aid] = rec
        return rec

    # ---------------------------------------------------------- access
    def get(self, artifact_id: str, session_id: str) -> ArtifactRecord:
        rec = self._records.get(artifact_id)
        if rec is None or rec.owner not in ("operator", session_id):
            raise NiFiMCPError(ErrorCode.OUT_OF_SCOPE, "artifact is not registered for this session",
                               "Use an artifact ID listed by get_capabilities or created in this session.")
        created = dt.datetime.fromisoformat(rec.created_at.replace("Z", "+00:00"))
        if utc_now() - created > self.retention:
            raise NiFiMCPError(ErrorCode.STALE_ARTIFACT, "artifact is past the configured retention period")
        return rec

    def path_of(self, rec: ArtifactRecord) -> Path:
        path = (self.root / rec.relpath).resolve()
        if self.root.resolve() not in path.parents:
            raise NiFiMCPError(ErrorCode.STALE_ARTIFACT, "artifact location is invalid")
        return path

    def read_bytes(self, artifact_id: str, session_id: str) -> tuple[ArtifactRecord, bytes]:
        rec = self.get(artifact_id, session_id)
        path = self.path_of(rec)
        if path.is_dir():
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "this artifact is a bundle directory, not a single file")
        if path.is_symlink() or not path.is_file():
            raise NiFiMCPError(ErrorCode.STALE_ARTIFACT, "artifact file is missing")
        data = path.read_bytes()
        if sha256_hex(data) != rec.sha256:
            raise NiFiMCPError(ErrorCode.STALE_ARTIFACT, "artifact changed since it was registered or created")
        return rec, data

    def verify_dir(self, rec: ArtifactRecord) -> Path:
        path = self.path_of(rec)
        parts = []
        for entry in sorted(path.iterdir()):
            if entry.is_symlink() or not entry.is_file():
                raise NiFiMCPError(ErrorCode.STALE_ARTIFACT, "registered bundle contains an unexpected entry")
            parts.append(f"{entry.name}:{sha256_hex(entry.read_bytes())}")
        if sha256_hex("\n".join(parts).encode()) != rec.sha256:
            raise NiFiMCPError(ErrorCode.STALE_ARTIFACT, "registered bundle changed since registration")
        return path

    def listing(self, session_id: str) -> list[dict]:
        return [r.public() for r in sorted(self._records.values(), key=lambda r: (r.created_at, r.artifact_id))
                if r.owner in ("operator", session_id)]

    def purge_expired(self) -> int:
        """Remove session folders older than the retention period. Returns folders removed."""
        removed = 0
        cutoff = utc_now() - self.retention
        for folder in (self.root / "sessions").iterdir():
            if folder.is_symlink() or not folder.is_dir():
                continue
            mtime = dt.datetime.fromtimestamp(folder.stat().st_mtime, dt.timezone.utc)
            if mtime < cutoff:
                shutil.rmtree(folder, ignore_errors=True)
                removed += 1
        return removed
