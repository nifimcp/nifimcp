"""Effective limits: operator defaults bounded by hard maxima in application code."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator

MiB = 1024 * 1024

# Hard maxima from the build specification. Operators cannot raise these.
HARD = {
    "time_window_minutes": 1440,
    "provenance_events": 1000,
    "components": 2000,
    "depth": 8,
    "sample_size": 25,
    "concurrency": 2,
    "tool_timeout_seconds": 60,
    "result_bytes": 256 * 1024,
    "bundle_expanded_bytes": 100 * MiB,
}

DEFAULTS = {
    "time_window_minutes": 60,
    "provenance_events": 200,
    "components": 500,
    "depth": 4,
    "sample_size": 10,
    "concurrency": 1,
    "tool_timeout_seconds": 30,
    "result_bytes": 256 * 1024,
    "bundle_expanded_bytes": 25 * MiB,
}

# Further fixed bounds that are not operator-configurable.
MAX_BUNDLE_FILES = 64
MAX_BUNDLE_COMPRESSION_RATIO = 100
MAX_SINGLE_JSON_BYTES = 25 * MiB
MAX_GROUP_NESTING = 32
MAX_CURSOR_TTL_SECONDS = 900
MAX_BULLETINS = 500
MAX_BULLETIN_MESSAGE_CHARS = 500
MAX_ARTIFACTS_PER_SESSION = 200
# Raw live responses are kept separately and rotate oldest-first, so long live sessions never stall.
MAX_RAW_OBSERVATIONS_PER_SESSION = 500


class LimitsConfig(BaseModel):
    """Operator limits. Accepts the documented example's key style.

    ``x`` sets the default/effective value; ``maximum_x`` may lower the operator's
    ceiling. Neither may exceed the hard maximum.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    time_window_minutes: int = DEFAULTS["time_window_minutes"]
    maximum_time_window_minutes: int = HARD["time_window_minutes"]
    provenance_events: int = DEFAULTS["provenance_events"]
    maximum_provenance_events: int = HARD["provenance_events"]
    components: int = DEFAULTS["components"]
    maximum_components: int = HARD["components"]
    depth: int = DEFAULTS["depth"]
    maximum_depth: int = HARD["depth"]
    queue_sampling_enabled: bool = False
    sample_size: int = DEFAULTS["sample_size"]
    maximum_sample_size: int = HARD["sample_size"]
    concurrency: int = DEFAULTS["concurrency"]
    maximum_concurrency: int = HARD["concurrency"]
    tool_timeout_seconds: int = DEFAULTS["tool_timeout_seconds"]
    maximum_timeout_seconds: int = HARD["tool_timeout_seconds"]
    maximum_result_bytes: int = HARD["result_bytes"]
    bundle_expanded_bytes: int = DEFAULTS["bundle_expanded_bytes"]
    maximum_bundle_expanded_bytes: int = HARD["bundle_expanded_bytes"]

    @model_validator(mode="after")
    def _bounded(self):
        pairs = [
            ("time_window_minutes", "maximum_time_window_minutes", "time_window_minutes"),
            ("provenance_events", "maximum_provenance_events", "provenance_events"),
            ("components", "maximum_components", "components"),
            ("depth", "maximum_depth", "depth"),
            ("sample_size", "maximum_sample_size", "sample_size"),
            ("concurrency", "maximum_concurrency", "concurrency"),
            ("tool_timeout_seconds", "maximum_timeout_seconds", "tool_timeout_seconds"),
            ("bundle_expanded_bytes", "maximum_bundle_expanded_bytes", "bundle_expanded_bytes"),
        ]
        for value_key, max_key, hard_key in pairs:
            value, ceiling, hard = getattr(self, value_key), getattr(self, max_key), HARD[hard_key]
            if not (1 <= value <= ceiling <= hard):
                raise ValueError(f"{value_key} must satisfy 1 <= value <= {max_key} <= {hard}")
        if not (1024 <= self.maximum_result_bytes <= HARD["result_bytes"]):
            raise ValueError(f"maximum_result_bytes must be between 1024 and {HARD['result_bytes']}")
        return self

    def as_public(self) -> dict:
        return {
            "time_window_minutes": {"default": self.time_window_minutes, "maximum": self.maximum_time_window_minutes},
            "provenance_events": {"default": self.provenance_events, "maximum": self.maximum_provenance_events},
            "components_per_scope": {"default": self.components, "maximum": self.maximum_components},
            "graph_depth": {"default": self.depth, "maximum": self.maximum_depth},
            "queue_metadata_sample": {"enabled": self.queue_sampling_enabled, "default": self.sample_size,
                                      "maximum": self.maximum_sample_size},
            "active_observation_requests": {"default": self.concurrency, "maximum": self.maximum_concurrency},
            "tool_wall_time_seconds": {"default": self.tool_timeout_seconds, "maximum": self.maximum_timeout_seconds},
            "model_visible_result_bytes": self.maximum_result_bytes,
            "bundle_expanded_bytes": {"default": self.bundle_expanded_bytes,
                                      "maximum": self.maximum_bundle_expanded_bytes},
        }
