"""Bounded parsing of untrusted JSON.

Rejects: oversized input, invalid UTF-8, duplicate object keys, non-finite
numbers, excessive nesting depth and excessive element counts. Nothing is
silently dropped or truncated.
"""
from __future__ import annotations

import json
from typing import Any

MAX_DEPTH = 128
MAX_ELEMENTS = 2_000_000


class UnsafeJSON(ValueError):
    """Input rejected by bounded JSON parsing. Message never echoes input content."""


def _reject_constant(_value):
    raise UnsafeJSON("non-finite JSON numbers are not accepted")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeJSON("duplicate JSON object key")
        result[key] = value
    return result


def _check_depth(raw: str, max_depth: int) -> None:
    """Pre-scan nesting depth without building objects (guards recursion)."""
    depth = 0
    in_string = False
    escape = False
    for ch in raw:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                raise UnsafeJSON(f"JSON nesting exceeds {max_depth} levels")
        elif ch in "]}":
            depth -= 1


def _count(value: Any, limit: int) -> int:
    total = 0
    stack = [value]
    while stack:
        item = stack.pop()
        total += 1
        if total > limit:
            raise UnsafeJSON(f"JSON exceeds {limit} elements")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return total


def loads_bounded(data: bytes, *, max_bytes: int, max_depth: int = MAX_DEPTH,
                  max_elements: int = MAX_ELEMENTS) -> Any:
    if not isinstance(data, (bytes, bytearray)):
        raise UnsafeJSON("expected bytes")
    if len(data) > max_bytes:
        raise UnsafeJSON(f"JSON input exceeds {max_bytes} bytes")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafeJSON("JSON input is not valid UTF-8") from exc
    if text.startswith("﻿"):
        text = text[1:]
    _check_depth(text, max_depth)
    try:
        value = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique)
    except UnsafeJSON:
        raise
    except (ValueError, RecursionError) as exc:
        raise UnsafeJSON("malformed JSON") from exc
    _count(value, max_elements)
    return value
