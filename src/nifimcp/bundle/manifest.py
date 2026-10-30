"""Versioned offline evidence bundle manifest (schema ``nifimcp-bundle/1``)."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..util import parse_iso

SCOPE_RE = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
FILE_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$"
FileKind = Literal["flow_definition", "status", "bulletins", "provenance", "queue_sample", "operator_notes"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Collector(_Strict):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    version: Annotated[str, Field(min_length=1, max_length=64)]


class NiFiInfo(_Strict):
    version: Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+$")]
    profile: Annotated[str, Field(min_length=1, max_length=200)]


class DeclaredScope(_Strict):
    scope_id: Annotated[str, Field(pattern=SCOPE_RE)]
    process_group_id: Annotated[str, Field(min_length=1, max_length=128)]
    label: Annotated[str, Field(max_length=200)] = ""


class NodeCoverage(_Strict):
    node_id: Annotated[str, Field(min_length=1, max_length=128)]
    included: bool
    note: Annotated[str, Field(max_length=500)] = ""


class Interval(_Strict):
    start: str
    end: str

    @model_validator(mode="after")
    def _ok(self):
        if parse_iso(self.end) <= parse_iso(self.start):
            raise ValueError("interval end must follow start")
        return self


class BundleFile(_Strict):
    path: Annotated[str, Field(pattern=FILE_RE)]
    kind: FileKind
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    bytes: Annotated[int, Field(ge=1, le=100 * 1024 * 1024)]
    collected_at: str
    node_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    interval: Interval | None = None
    origin: Literal["machine_collected", "human_transcribed"] = "machine_collected"
    description: Annotated[str, Field(max_length=500)] = ""

    @field_validator("collected_at")
    @classmethod
    def _ts(cls, v: str) -> str:
        parse_iso(v)
        return v


class RedactionDeclaration(_Strict):
    policy: Annotated[str, Field(min_length=1, max_length=200)]
    sensitive_values_present: bool
    notes: Annotated[str, Field(max_length=1000)] = ""


class Completeness(_Strict):
    status: Literal["complete", "partial"]
    missing: Annotated[list[Annotated[str, Field(max_length=500)]], Field(max_length=50)] = []


class BundleManifest(_Strict):
    bundle_schema: Literal["nifimcp-bundle/1"]
    bundle_id: Annotated[str, Field(pattern=SCOPE_RE)]
    created_at: str
    collector: Collector
    nifi: NiFiInfo
    declared_scope: DeclaredScope
    nodes: Annotated[list[NodeCoverage], Field(min_length=1, max_length=64)]
    source_kinds: Annotated[list[FileKind], Field(min_length=1, max_length=6)]
    files: Annotated[list[BundleFile], Field(min_length=1, max_length=64)]
    redaction: RedactionDeclaration
    completeness: Completeness

    @field_validator("created_at")
    @classmethod
    def _ts(cls, v: str) -> str:
        parse_iso(v)
        return v

    @model_validator(mode="after")
    def _consistency(self):
        paths = [f.path for f in self.files]
        if len(set(p.lower() for p in paths)) != len(paths):
            raise ValueError("duplicate file paths in manifest")
        kinds = {f.kind for f in self.files}
        if kinds != set(self.source_kinds):
            raise ValueError("source_kinds must equal the kinds of the listed files")
        if "flow_definition" not in kinds:
            raise ValueError("a bundle must include at least one flow_definition file")
        node_ids = {n.node_id for n in self.nodes}
        for f in self.files:
            if f.node_id is not None and f.node_id not in node_ids:
                raise ValueError("file node_id must be declared in nodes")
        if any(not n.included for n in self.nodes) and self.completeness.status != "partial":
            raise ValueError("a bundle with excluded nodes must declare partial completeness")
        return self
