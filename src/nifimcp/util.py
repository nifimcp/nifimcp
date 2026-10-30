"""Small shared helpers: canonical JSON, hashing and UTC time handling."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: dt.datetime | None) -> str | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        raise ValueError("naive datetime")
    return ts.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> dt.datetime:
    """Parse an RFC 3339 timestamp that MUST carry a timezone."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("timestamp must be an RFC 3339 string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def parse_nifi_time(value: str) -> dt.datetime | None:
    """Parse NiFi's 'MM/dd/yyyy HH:mm:ss.SSS UTC' style timestamps (UTC only)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    for fmt in ("%m/%d/%Y %H:%M:%S.%f %Z", "%m/%d/%Y %H:%M:%S %Z"):
        try:
            parsed = dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
        if not text.endswith(("UTC", "GMT")):
            return None
        return parsed.replace(tzinfo=dt.timezone.utc)
    return None


def nifi_time(ts: dt.datetime) -> str:
    """Format a UTC datetime the way NiFi 2.12.0 provenance requests accept."""
    return ts.astimezone(dt.timezone.utc).strftime("%m/%d/%Y %H:%M:%S UTC")


def short_hash(*parts: str, length: int = 20) -> str:
    return sha256_hex("\x1f".join(parts).encode("utf-8"))[:length]
