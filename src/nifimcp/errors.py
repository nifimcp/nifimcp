"""Standard, sanitized error model.

Messages are built from fixed text plus validated identifiers only. They never
contain tokens, HTTP response bodies, file contents or filesystem secrets.
"""
from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNSUPPORTED_TOPOLOGY = "UNSUPPORTED_TOPOLOGY"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    TIMEOUT = "TIMEOUT"
    QUERY_FAILED = "QUERY_FAILED"
    INVALID_BUNDLE = "INVALID_BUNDLE"
    STALE_ARTIFACT = "STALE_ARTIFACT"
    VALIDATION_FAILED = "VALIDATION_FAILED"


DEFAULT_NEXT_STEP = {
    ErrorCode.INVALID_ARGUMENT: "Correct the arguments to match the tool's input schema and retry.",
    ErrorCode.OUT_OF_SCOPE: "Use an identifier that belongs to a configured scope; call get_capabilities to list scopes.",
    ErrorCode.PERMISSION_DENIED: "Ask the NiFi administrator to grant the observer identity the documented read policy, or continue without this capability.",
    ErrorCode.UNSUPPORTED_VERSION: "Use NiFi 2.12.0 or an offline bundle collected from a qualified version.",
    ErrorCode.UNSUPPORTED_TOPOLOGY: "Live investigation of clustered NiFi is not qualified in this release; use an offline bundle that declares node coverage.",
    ErrorCode.LIMIT_EXCEEDED: "Narrow the scope, interval or depth and retry.",
    ErrorCode.TIMEOUT: "Retry with a narrower interval; the server cleaned up any request it created.",
    ErrorCode.QUERY_FAILED: "Check NiFi availability and the operator configuration with `nifimcp doctor`.",
    ErrorCode.INVALID_BUNDLE: "Recreate the bundle with a valid manifest and hashes, then register it again.",
    ErrorCode.STALE_ARTIFACT: "Re-register or regenerate the artifact in this session.",
    ErrorCode.VALIDATION_FAILED: "Fix the reported errors and validate again.",
}


class NiFiMCPError(Exception):
    """An error safe to show to the MCP host."""

    def __init__(self, code: ErrorCode, message: str, next_step: str | None = None):
        super().__init__(message)
        self.code = ErrorCode(code)
        self.message = message[:2000]
        self.next_step = (next_step or DEFAULT_NEXT_STEP[self.code])[:2000]

    def as_dict(self) -> dict:
        return {"code": self.code.value, "message": self.message, "next_step": self.next_step}

    def __repr__(self) -> str:  # never leak extra state into logs
        return f"NiFiMCPError({self.code.value})"
