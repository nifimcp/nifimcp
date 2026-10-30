"""Redaction applied before tool output, logging, report generation and export.

Strategy: classify each value; when a value cannot be safely classified it is
omitted and the omission is recorded. Pattern-based masking of free text is
best-effort: it covers common credential shapes, not every possible secret. Sensitive descriptors, secret-looking
property names, sensitive parameters, URL userinfo, bearer tokens and
unapproved attribute values never leave this module.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..config import RedactionPolicy
from ..limits import MAX_BULLETIN_MESSAGE_CHARS

MASK = "[REDACTED]"
SECRET_NAME = re.compile(
    r"(?:pass(?:word|wd|phrase)?|secret|token|credential|private[._ -]?key|api[._ -]?key|access[._ -]?key|"
    r"auth(?:orization)?|keystore|truststore|bearer|session[._ -]?id|cookie|signature|jwt|sas)",
    re.IGNORECASE,
)
URL_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^\s/@]+@", re.IGNORECASE)
KEY_VALUE_SECRET = re.compile(
    r"((?:pass(?:word|wd|phrase)?|secret|token|api[._-]?key|access[._-]?key|authorization|credential)s?"
    r"\s*[:=]\s*)(?![$#]\{)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)",
    re.IGNORECASE,
)
BEARER = re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
# Credential-bearing URL query parameters (cloud presigned URLs, SAS tokens, API keys in query strings).
URL_QUERY_SECRET = re.compile(
    r"([?&;](?:sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|"
    r"x-goog-credential|code|key|api[_-]?key|apikey|access[_-]?token|token|auth|"
    r"client[_-]?secret|password|pwd)=)(?![$#]\{)([^&#\s\"']+)",   # ${EL} and #{param} references stay visible
    re.IGNORECASE,
)
# Well-known secret shapes that appear outside key=value form.
KNOWN_SECRET_SHAPES = re.compile(
    r"(hooks\.slack\.com/services/|discord(?:app)?\.com/api/webhooks/|\.webhook\.office\.com/webhookb2/)[A-Za-z0-9/@_-]+|"
    r"\bglpat-[A-Za-z0-9_-]{20,}|"
    r"\bAIza[0-9A-Za-z_-]{30,}|"
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{30,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{30,}|"
    r"\bxox[abposr]-[A-Za-z0-9-]{10,}|"
    r"\bsk-[A-Za-z0-9_-]{20,}|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)
LONG_OPAQUE = re.compile(r"\b[A-Za-z0-9+/_=-]{40,}\b")
PARAM_ONLY = re.compile(r"^\s*#\{[^}]{1,256}\}\s*$")
EL_ONLY = re.compile(r"^\s*\$\{[^}]{1,2048}\}\s*$")


def scrub_text(text: str, *, opaque: bool = False) -> tuple[str, bool]:
    """Mask credentials embedded in free text. Returns (text, changed).

    ``opaque`` additionally masks long opaque tokens; it is used for runtime text
    (bulletins, attribute values) but not for configuration expressions, which
    must be preserved exactly.
    """
    original = text
    text = URL_USERINFO.sub(r"\1" + MASK + "@", text)
    text = KEY_VALUE_SECRET.sub(lambda m: m.group(1) + MASK, text)
    text = BEARER.sub(lambda m: m.group(1) + " " + MASK, text)
    text = URL_QUERY_SECRET.sub(lambda m: m.group(1) + MASK, text)
    text = KNOWN_SECRET_SHAPES.sub(lambda m: (m.group(1) or "") + MASK, text)
    if opaque:
        text = LONG_OPAQUE.sub(MASK, text)
    return text, text != original


_PROCESS_KEY = secrets.token_bytes(32)


def fingerprint(value: str, key: bytes | None = None) -> str:
    """Correlation label for a hidden value, keyed per session so it cannot confirm guesses.

    Equal values give equal labels within one session; labels from different sessions are unrelated.
    """
    digest = hmac.new(key or _PROCESS_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return "hmac:" + digest


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME.search(name or ""))


def secret_like_unknown(key: str, descriptor: dict | None) -> bool:
    """A secret-like name whose sensitivity NiFi has not declared.

    Static properties that the component declares non-sensitive are trusted (for
    example "Response Cookie Strategy"). Dynamic properties and properties with no
    descriptor are treated as possibly secret when their name looks secret-like.
    """
    descriptor = descriptor or {}
    names = (key, str(descriptor.get("displayName") or ""))
    if not any(is_secret_name(n) for n in names):
        return False
    declared_static = descriptor.get("sensitive") is False and descriptor.get("dynamic") is False
    return not declared_static


@dataclass
class RedactionLedger:
    """Records what was withheld so reports can disclose omissions."""

    masked_pointers: set[str] = field(default_factory=set)
    omitted_fields: dict[str, int] = field(default_factory=dict)

    def mask(self, pointer: str) -> None:
        self.masked_pointers.add(pointer)

    def omit(self, reason: str, count: int = 1) -> None:
        self.omitted_fields[reason] = self.omitted_fields.get(reason, 0) + count

    def summary(self) -> dict:
        return {"masked_value_count": len(self.masked_pointers),
                "omitted": dict(sorted(self.omitted_fields.items()))}


class Redactor:
    def __init__(self, policy: RedactionPolicy, key: bytes | None = None):
        self.policy = policy
        self.key = key or _PROCESS_KEY
        self.ledger = RedactionLedger()

    # -- names ---------------------------------------------------------------
    def name(self, value: Any, pointer: str = "") -> str | None:
        if value is None:
            return None
        if not self.policy.include_component_names:
            self.ledger.omit("component_names")
            return None
        text, changed = scrub_text(str(value)[:512])
        if changed:
            self.ledger.mask(pointer or "name")
        return text

    # -- properties -----------------------------------------------------------
    def property_value(self, key: str, value: Any, descriptor: dict | None, pointer: str) -> dict:
        """Return a safe description of one processor/service property value."""
        descriptor = descriptor or {}
        if value is None:
            return {"state": "unset"}
        if not isinstance(value, str):
            self.ledger.omit("non_string_property_values")
            return {"state": "omitted", "reason": "unclassified value type"}
        if PARAM_ONLY.fullmatch(value):
            return {"state": "parameter_reference", "value": value.strip()}
        if descriptor.get("sensitive") is True or (secret_like_unknown(key, descriptor)):
            self.ledger.mask(pointer)
            return {"state": "masked", "reason": "sensitive or secret-like property"}
        if not self.policy.include_property_values:
            self.ledger.omit("property_values")
            return {"state": "omitted", "reason": "property values excluded by redaction policy"}
        text, changed = scrub_text(value)
        if changed:
            self.ledger.mask(pointer)
        if len(text) > 4096:
            self.ledger.omit("oversized_property_values")
            return {"state": "omitted", "reason": "value longer than 4096 characters",
                    "length": len(value), "fingerprint": fingerprint(value, self.key)}
        return {"state": "value", "value": text, "scrubbed": changed}

    def parameter(self, name: str, parameter: dict, pointer: str) -> dict:
        sensitive = bool(parameter.get("sensitive")) or is_secret_name(name)
        has_value = parameter.get("value") is not None
        out = {"name": self.name(name, pointer), "sensitive": sensitive, "has_value": has_value}
        if has_value and not sensitive and self.policy.include_parameter_values:
            text, changed = scrub_text(str(parameter.get("value")))
            out["value"] = text
            if changed:
                self.ledger.mask(pointer)
        elif has_value:
            self.ledger.mask(pointer)
        return out

    # -- runtime data ----------------------------------------------------------
    def bulletin_message(self, message: Any) -> str | None:
        if message is None:
            return None
        if not self.policy.include_bulletin_messages:
            self.ledger.omit("bulletin_messages")
            return None
        text, changed = scrub_text(str(message), opaque=True)
        if changed:
            self.ledger.omit("bulletin_secret_fragments")
        if not self.policy.include_filenames:
            # NiFi bulletins often embed FlowFile[filename=...]
            text, n = re.subn(r"filename=[^,\]\s]+", "filename=" + MASK, text)
            if n:
                self.ledger.omit("bulletin_filenames", n)
        if len(text) > MAX_BULLETIN_MESSAGE_CHARS:
            self.ledger.omit("bulletin_message_truncated")
            text = text[:MAX_BULLETIN_MESSAGE_CHARS] + " [truncated by NiFiMCP]"
        return text

    def filename(self, value: Any) -> dict | None:
        if value is None:
            return None
        if self.policy.include_filenames:
            text, changed = scrub_text(str(value)[:1024])
            return {"value": text}
        self.ledger.omit("filenames")
        return {"fingerprint": fingerprint(str(value), self.key)}

    def attributes(self, attributes: list[dict] | dict | None) -> dict:
        """Provenance attributes: only allowlisted names keep values."""
        if not attributes:
            return {}
        items = attributes.items() if isinstance(attributes, dict) else (
            (a.get("name"), a.get("value")) for a in attributes if isinstance(a, dict))
        kept, hidden = {}, 0
        allow = set(self.policy.attribute_allowlist)
        for key, value in items:
            if not isinstance(key, str):
                continue
            if key in allow and not is_secret_name(key) and isinstance(value, str):
                text, changed = scrub_text(value[:1024], opaque=True)
                kept[key] = text
                if changed:
                    self.ledger.omit("attribute_secret_fragments")
            else:
                hidden += 1
        if hidden:
            self.ledger.omit("attribute_values_not_allowlisted", hidden)
        return kept

    def endpoint(self, value: str, pointer: str) -> str:
        text, changed = scrub_text(value)
        if changed:
            self.ledger.mask(pointer)
        return text
