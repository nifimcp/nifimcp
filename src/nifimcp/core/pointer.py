"""RFC 6901 JSON Pointer helpers."""
from __future__ import annotations

from typing import Any


class PointerError(LookupError):
    pass


def escape(token: str | int) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def join(base: str, *tokens: str | int) -> str:
    return base + "".join("/" + escape(t) for t in tokens)


def resolve(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise PointerError("invalid JSON pointer")
    value = document
    for raw in pointer[1:].split("/"):
        token = unescape(raw)
        if isinstance(value, dict):
            if token not in value:
                raise PointerError("pointer does not resolve")
            value = value[token]
        elif isinstance(value, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise PointerError("pointer does not resolve")
            index = int(token)
            if index >= len(value):
                raise PointerError("pointer does not resolve")
            value = value[index]
        else:
            raise PointerError("pointer does not resolve")
    return value
