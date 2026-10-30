"""Pydantic types equivalent to the public JSON Schemas in ``contracts/``.

Contract tests (tests/unit/test_contracts.py) check that these models and the
JSON Schemas accept and reject the same instances. Unknown fields fail.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .util import parse_iso

SCOPE_RE = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
HASH_RE = r"^[0-9a-f]{64}$"
ARTIFACT_RE = r"^art_[A-Za-z0-9_-]{16,80}$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# ----------------------------------------------------------------- envelope
EvidenceKind = Literal["configuration", "status", "bulletin", "provenance", "queue_sample", "operator_note", "lab_result"]
FindingKind = Literal["observed", "deterministic_rule", "hypothesis", "operator_assertion"]
Severity = Literal["info", "review", "warning", "error"]


def _rfc3339(value: str | None) -> str | None:
    if value is not None:
        parse_iso(value)
    return value


class EvidenceRecord(Strict):
    evidence_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: EvidenceKind
    source_id: Annotated[str, Field(min_length=1, max_length=128)]
    component_id: Annotated[str | None, Field(max_length=128)]
    node_id: Annotated[str | None, Field(max_length=128)]
    event_time: str | None
    collected_at: str
    source_hash: Annotated[str, Field(pattern=HASH_RE)]
    source_pointer: Annotated[str, Field(max_length=4096)]
    facts: dict[str, Any]

    _t1 = field_validator("event_time")(classmethod(lambda cls, v: _rfc3339(v)))
    _t2 = field_validator("collected_at")(classmethod(lambda cls, v: _rfc3339(v)))


class Finding(Strict):
    finding_id: Annotated[str, Field(min_length=1, max_length=128)]
    statement: Annotated[str, Field(max_length=4000)]
    kind: FindingKind
    severity: Severity
    evidence_ids: Annotated[list[Annotated[str, Field(min_length=1, max_length=128)]], Field(max_length=100)]
    limitations: Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=30)]


class Gap(Strict):
    code: Annotated[str, Field(min_length=1, max_length=128)]
    detail: Annotated[str, Field(max_length=2000)]


class ErrorObject(Strict):
    code: Annotated[str, Field(min_length=1, max_length=128)]
    message: Annotated[str, Field(max_length=2000)]
    next_step: Annotated[str, Field(max_length=2000)]


class Envelope(Strict):
    schema_version: Literal["1"]
    request_id: Annotated[str, Field(min_length=1, max_length=128)]
    mode: Literal["demo", "bundle", "live"]
    status: Literal["ok", "partial", "error"]
    scope: Annotated[str, Field(pattern=SCOPE_RE)]
    source_version: Annotated[str | None, Field(max_length=128)]
    collected_at: str
    evidence: Annotated[list[EvidenceRecord], Field(max_length=2000)]
    findings: Annotated[list[Finding], Field(max_length=500)]
    gaps: Annotated[list[Gap], Field(max_length=200)]
    limits_applied: dict[str, Any]
    data: dict[str, Any]
    error: ErrorObject | None

    _t = field_validator("collected_at")(classmethod(lambda cls, v: _rfc3339(v)))

    @model_validator(mode="after")
    def _error_consistency(self):
        if (self.status == "error") != (self.error is not None):
            raise ValueError("status 'error' and a non-null error must go together")
        return self


# ----------------------------------------------------------------- FlowPlan
IdStr = Annotated[str, Field(pattern=SCOPE_RE)]
RelStr = Annotated[str, Field(min_length=1, max_length=128)]


class PlanComponent(Strict):
    id: IdStr
    type_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: Literal["processor", "input_port", "output_port"]
    properties: Annotated[dict[str, Annotated[str, Field(max_length=8192)]], Field(max_length=50)]
    auto_terminated_relationships: Annotated[list[RelStr], Field(max_length=20)]

    @field_validator("auto_terminated_relationships")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("auto_terminated_relationships must be unique")
        return value


class PlanConnection(Strict):
    id: IdStr
    source: IdStr
    relationship: RelStr
    destination: IdStr


class ParameterReference(Strict):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    sensitive: bool


class OutputExpectation(Strict):
    port_id: IdStr
    condition: Annotated[str, Field(max_length=2000)]


class FlowPlan(Strict):
    schema_version: Literal["1"]
    target_version: Literal["2.12.0"]
    catalog_hash: Annotated[str, Field(pattern=HASH_RE)]
    intent: Annotated[str, Field(min_length=1, max_length=2000)]
    blueprint: Literal["attribute_router", "json_field_gate"]
    automatic_start: Literal[False]
    components: Annotated[list[PlanComponent], Field(min_length=2, max_length=20)]
    connections: Annotated[list[PlanConnection], Field(min_length=1, max_length=50)]
    parameter_references: Annotated[list[ParameterReference], Field(max_length=30)]
    output_expectations: Annotated[list[OutputExpectation], Field(max_length=20)]


# ----------------------------------------------------------------- tool inputs
class Interval(Strict):
    start: str
    end: str

    @model_validator(mode="after")
    def _times(self):
        start, end = parse_iso(self.start), parse_iso(self.end)
        if end <= start:
            raise ValueError("interval end must be after start")
        return self


class GetCapabilitiesArgs(Strict):
    pass


class DescribeFlowArgs(Strict):
    scope_id: IdStr
    depth: Annotated[int, Field(ge=1, le=8)] = 4
    cursor: Annotated[str, Field(max_length=1024)] | None = None


class GetFlowHealthArgs(Strict):
    scope_id: IdStr
    interval: Interval | None = None


class SelectorUUID(Strict):
    kind: Literal["flowfile_uuid"]
    value: str

    @field_validator("value")
    @classmethod
    def _uuid(cls, v: str) -> str:
        return str(uuid.UUID(v))


class SelectorFilename(Strict):
    kind: Literal["filename"]
    value: Annotated[str, Field(min_length=1, max_length=1024)]


class SelectorAttribute(Strict):
    kind: Literal["indexed_attribute"]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    value: Annotated[str, Field(min_length=1, max_length=1024)]


Selector = Annotated[Union[SelectorUUID, SelectorFilename, SelectorAttribute], Field(discriminator="kind")]


class TraceFeedArgs(Strict):
    scope_id: IdStr
    selector: Selector
    interval: Interval


class InspectUnmatchedArgs(Strict):
    connection_id: str
    interval: Interval | None = None
    sample_metadata: bool = False

    @field_validator("connection_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        uuid.UUID(v)
        return v


class CompareSnapshotsArgs(Strict):
    baseline_artifact_id: Annotated[str, Field(pattern=ARTIFACT_RE)]
    candidate_artifact_id: Annotated[str, Field(pattern=ARTIFACT_RE)]


class ExportInvestigationArgs(Strict):
    investigation_id: Annotated[str, Field(min_length=1, max_length=128)]
    format: Literal["json", "html"]


class GetProcessorCatalogArgs(Strict):
    type_filter: Annotated[str, Field(min_length=1, max_length=128)] | None = None


class PlanArgs(Strict):
    plan: FlowPlan


TOOL_ARG_MODELS: dict[str, type[Strict]] = {
    "get_capabilities": GetCapabilitiesArgs,
    "describe_flow": DescribeFlowArgs,
    "get_flow_health": GetFlowHealthArgs,
    "trace_feed": TraceFeedArgs,
    "inspect_unmatched": InspectUnmatchedArgs,
    "compare_flow_snapshots": CompareSnapshotsArgs,
    "export_investigation": ExportInvestigationArgs,
    "get_processor_catalog": GetProcessorCatalogArgs,
    "validate_flow_plan": PlanArgs,
    "draft_flow": PlanArgs,
}
