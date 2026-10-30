"""Operator configuration. Read once per server process; never changed by tools."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .core.jsonsafe import UnsafeJSON, loads_bounded
from .errors import ErrorCode, NiFiMCPError
from .limits import LimitsConfig

SCOPE_ID_RE = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
ATTR_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ClientCertificateAuth(_Strict):
    kind: Literal["client_certificate"]
    cert_file: str
    key_file: str


class BearerTokenFileAuth(_Strict):
    kind: Literal["bearer_token_file"]
    token_file: str


class ScopeConfig(_Strict):
    scope_id: Annotated[str, Field(pattern=SCOPE_ID_RE)]
    process_group_id: Annotated[str, Field(pattern=UUID_RE)]
    label: Annotated[str, Field(max_length=200)] = ""


class ProvenanceConfig(_Strict):
    enabled: bool = True
    approved_indexed_attributes: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("approved_indexed_attributes")
    @classmethod
    def _names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not ATTR_NAME_RE.fullmatch(name):
                raise ValueError("approved indexed attribute names must be simple identifiers")
        return value


class LiveConfig(_Strict):
    origin: str
    ca_file: str
    auth: Annotated[ClientCertificateAuth | BearerTokenFileAuth, Field(discriminator="kind")]
    scopes: list[ScopeConfig] = Field(min_length=1, max_length=20)
    provenance: ProvenanceConfig = ProvenanceConfig()
    trusted_proxy: str | None = None
    expected_version: Literal["2.12.0"] = "2.12.0"

    @field_validator("origin")
    @classmethod
    def _origin(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            raise ValueError("live origin must use https")
        if parts.username or parts.password:
            raise ValueError("live origin must not contain userinfo")
        if not parts.hostname or parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("live origin must be scheme://host[:port] only")
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname   # IPv6 literal
        return f"https://{host}" + (f":{parts.port}" if parts.port else "")

    @field_validator("trusted_proxy")
    @classmethod
    def _proxy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("trusted_proxy must be http(s)://host:port without credentials")
        return value

    @model_validator(mode="after")
    def _unique_scopes(self):
        ids = [s.scope_id for s in self.scopes]
        groups = [s.process_group_id.lower() for s in self.scopes]
        if len(set(ids)) != len(ids) or len(set(groups)) != len(groups):
            raise ValueError("scope ids and process group ids must be unique")
        return self


class RedactionPolicy(_Strict):
    include_component_names: bool = True
    include_property_values: bool = True
    include_parameter_values: bool = False
    include_bulletin_messages: bool = True
    include_filenames: bool = False
    attribute_allowlist: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("attribute_allowlist")
    @classmethod
    def _names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not ATTR_NAME_RE.fullmatch(name):
                raise ValueError("attribute allowlist entries must be exact attribute names")
        return value


class RegisteredInput(_Strict):
    path: str
    kind: Literal["bundle", "flow_definition"]
    label: Annotated[str, Field(max_length=200)] = ""


class OperatorConfig(_Strict):
    schema_version: Literal["1"]
    mode: Literal["demo", "bundle", "live"]
    artifact_dir: str
    registered_inputs: list[RegisteredInput] = Field(default_factory=list, max_length=50)
    live: LiveConfig | None = None
    telemetry: Literal[False] = False
    updates: Literal[False] = False
    redaction: RedactionPolicy = RedactionPolicy()
    limits: LimitsConfig = LimitsConfig()
    retention_days: Annotated[int, Field(ge=1, le=3650)] = 30
    keep_raw_observations: bool = True

    # Absolute directory of the config file (set by loader, not by the file).
    base_dir: str = ""

    @model_validator(mode="after")
    def _mode_requirements(self):
        if self.mode == "live" and self.live is None:
            raise ValueError("live mode requires a 'live' section")
        if self.mode != "live" and self.live is not None:
            raise ValueError("'live' section is only allowed in live mode")
        return self

    def resolve(self, path: str) -> Path:
        candidate = Path(os.path.expanduser(path))
        if not candidate.is_absolute():
            candidate = Path(self.base_dir) / candidate
        return candidate.resolve()

    @property
    def artifact_path(self) -> Path:
        return self.resolve(self.artifact_dir)


def load_config(path: str | os.PathLike) -> OperatorConfig:
    file = Path(path).expanduser().resolve()
    try:
        raw = file.read_bytes()
    except OSError as exc:
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "operator configuration file could not be read",
                           "Check the --config path.") from exc
    try:
        data = loads_bounded(raw, max_bytes=1024 * 1024, max_depth=16)
    except UnsafeJSON as exc:
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, f"operator configuration is not valid JSON ({exc})",
                           "Fix the configuration JSON.") from exc
    if not isinstance(data, dict):
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "operator configuration must be a JSON object")
    if "base_dir" in data:
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "operator configuration may not set base_dir")
    data["base_dir"] = str(file.parent)
    try:
        return OperatorConfig.model_validate(data)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})[:10]
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT,
                           "operator configuration failed validation at: " + ", ".join(fields),
                           "Compare with config/operator.example.json and docs/CONFIGURATION.md.") from exc
