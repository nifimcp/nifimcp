"""Allowlisted HTTPS transport to exactly one operator-configured NiFi origin.

* Only the 14 endpoints in contracts/nifi-2.12.0-rest-allowlist.json can be called,
  each with its fixed method and allowed query parameters. There is no passthrough.
* Path parameters must be UUIDs. Absolute URLs returned by NiFi are never followed.
* TLS certificate and hostname verification are always on; there is no skip option.
* Redirects are refused. Ambient proxy settings are ignored unless the operator
  configures a trusted proxy.
* Only safe GETs are retried, with bounded backoff. POSTs are never retried.
* Credentials are read from operator files and never logged or returned.
"""
from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import anyio
import httpx2

from ..config import LiveConfig, OperatorConfig
from ..errors import ErrorCode, NiFiMCPError
from ..util import sha256_hex

UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PARAM = re.compile(r"\{([a-z-]+)\}")
DEFAULT_MAX_RESPONSE = 8 * 1024 * 1024
DOWNLOAD_MAX_RESPONSE = 25 * 1024 * 1024


def load_allowlist() -> dict[str, dict]:
    doc = json.loads((resources.files("nifimcp") / "contracts" / "nifi-2.12.0-rest-allowlist.json").read_text())
    return {e["id"]: e for e in doc["endpoints"]}


@dataclass
class Response:
    endpoint: str
    status: int
    raw: bytes
    data: Any

    @property
    def sha256(self) -> str:
        return sha256_hex(self.raw)


def build_ssl_context(live: LiveConfig, config: OperatorConfig) -> ssl.SSLContext:
    ca = config.resolve(live.ca_file)
    if not ca.is_file():
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "configured CA file is not readable",
                           "Point live.ca_file at the PEM CA bundle that signs the NiFi server certificate.")
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if live.auth.kind == "client_certificate":
        cert, key = config.resolve(live.auth.cert_file), config.resolve(live.auth.key_file)
        try:
            ctx.load_cert_chain(str(cert), str(key))
        except (OSError, ssl.SSLError) as exc:
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "client certificate or key could not be loaded",
                               "Check live.auth.cert_file and live.auth.key_file (PEM, readable by this user).") from exc
    return ctx


def read_token(path: Path) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "bearer token file could not be read") from exc
    if not token or len(token) > 16384 or any(c.isspace() for c in token):
        raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "bearer token file does not contain a single token")
    return token


class NiFiHTTP:
    def __init__(self, config: OperatorConfig, *, transport: httpx2.AsyncBaseTransport | None = None):
        live = config.live
        if live is None:
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "live configuration missing")
        self.origin = live.origin
        self.allowlist = load_allowlist()
        headers = {"Accept": "application/json", "User-Agent": "nifimcp-observer"}
        self.identity_kind = live.auth.kind
        if live.auth.kind == "bearer_token_file":
            self._token_path = config.resolve(live.auth.token_file)
            headers["Authorization"] = "Bearer " + read_token(self._token_path)
        kwargs: dict[str, Any] = {}
        if transport is not None:
            kwargs["transport"] = transport
        else:
            kwargs["verify"] = build_ssl_context(live, config)
            if live.trusted_proxy:
                kwargs["proxy"] = live.trusted_proxy
        self._client_args = dict(base_url=self.origin + "/nifi-api", headers=headers, trust_env=False,
                                 follow_redirects=False, timeout=httpx2.Timeout(20.0, connect=10.0), **kwargs)
        self._client_obj: httpx2.AsyncClient | None = None
        self._client_loop: int | None = None
        self.identity_fingerprint = sha256_hex((self.origin + "|" + live.auth.kind + "|" + (
            getattr(live.auth, "cert_file", "") or getattr(live.auth, "token_file", ""))).encode())[:16]

    @property
    def _client(self) -> httpx2.AsyncClient:
        """One connection pool per event loop (a pool cannot be shared across loops)."""
        import asyncio
        loop = id(asyncio.get_running_loop())
        if self._client_obj is None or self._client_loop != loop:
            self._client_obj = httpx2.AsyncClient(**self._client_args)
            self._client_loop = loop
        return self._client_obj

    async def aclose(self) -> None:
        if self._client_obj is not None:
            await self._client_obj.aclose()
            self._client_obj = None

    def _path(self, entry: dict, params: dict[str, str]) -> str:
        template = entry["path"]
        names = PARAM.findall(template)
        if set(names) != set(params):
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "internal: endpoint parameters do not match the allowlist")
        path = template
        for name in names:
            value = params[name]
            if not isinstance(value, str) or not UUID.fullmatch(value):
                raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "identifiers must be UUIDs")
            path = path.replace("{" + name + "}", value)
        if "//" in path or ".." in path or "://" in path or not path.startswith("/"):
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "internal: unsafe path")
        return path

    def _query(self, entry: dict, query: dict[str, str] | None) -> dict[str, str]:
        out = {}
        for key, value in (query or {}).items():
            spec = entry["query"].get(key)
            if spec is None:
                raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "internal: query parameter not allowlisted")
            text = str(value)
            if spec == "int":
                if not text.isdigit() or int(text) > 100000:
                    raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "internal: integer query parameter out of range")
            elif text not in spec:
                raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "internal: query value not allowlisted")
            out[key] = text
        return out

    async def call(self, endpoint: str, *, params: dict[str, str] | None = None, query: dict[str, str] | None = None,
                   body: dict | None = None, max_bytes: int | None = None) -> Response:
        entry = self.allowlist.get(endpoint)
        if entry is None:
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "endpoint is not allowlisted")
        method = entry["method"]
        if (body is not None) != (method == "POST"):
            raise NiFiMCPError(ErrorCode.INVALID_ARGUMENT, "internal: request body only allowed for allowlisted POSTs")
        path = self._path(entry, params or {})
        q = self._query(entry, query)
        limit = max_bytes or (DOWNLOAD_MAX_RESPONSE if endpoint == "group_download" else DEFAULT_MAX_RESPONSE)
        attempts = 3 if method == "GET" else 1
        delay = 0.5
        for attempt in range(attempts):
            try:
                return await self._once(endpoint, method, path, q, body, limit)
            except _Retryable as exc:
                if attempt == attempts - 1:
                    raise exc.error from None
                await anyio.sleep(delay)
                delay *= 2
        raise NiFiMCPError(ErrorCode.QUERY_FAILED, "request failed")  # pragma: no cover

    async def _once(self, endpoint, method, path, query, body, limit) -> Response:
        try:
            request = self._client.build_request(method, path, params=query or None, json=body)
            response = await self._client.send(request, stream=True)
        except httpx2.TimeoutException as exc:
            err = NiFiMCPError(ErrorCode.TIMEOUT, "NiFi did not respond in time")
            if method == "GET":
                raise _Retryable(err) from exc
            raise _AmbiguousSubmission(err) from exc
        except httpx2.TransportError as exc:
            msg = "TLS verification failed for the configured origin" if "CERTIFICATE" in str(exc).upper() \
                or "SSL" in type(exc).__name__.upper() or "certificate" in str(exc).lower() else \
                "could not connect to the configured NiFi origin"
            err = NiFiMCPError(ErrorCode.QUERY_FAILED, msg, "Run `nifimcp doctor` to check origin, CA and identity.")
            if method == "GET" and "TLS" not in msg:
                raise _Retryable(err) from exc
            raise err from exc
        try:
            status = response.status_code
            if 300 <= status < 400:
                raise NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi answered with a redirect, which is refused",
                                   "Configure the exact NiFi origin; redirects and alternate origins are not followed.")
            chunks, total = [], 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > limit:
                    raise NiFiMCPError(ErrorCode.LIMIT_EXCEEDED, "NiFi response exceeded the size limit",
                                       "Narrow the scope or interval.")
                chunks.append(chunk)
            raw = b"".join(chunks)
        finally:
            await response.aclose()
        if status in (200, 201, 202):
            if not raw:
                return Response(endpoint, status, raw, {})
            try:
                data = json.loads(raw)
            except ValueError as exc:
                raise NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi returned malformed JSON") from exc
            return Response(endpoint, status, raw, data)
        if status == 401:
            raise NiFiMCPError(ErrorCode.PERMISSION_DENIED, "NiFi rejected the credential (missing, invalid or expired)",
                               "Renew the operator's credential file; NiFiMCP never falls back to another identity.")
        if status == 403:
            raise NiFiMCPError(ErrorCode.PERMISSION_DENIED, f"the observer identity lacks the NiFi policy for {endpoint}",
                               "Grant the documented read policy or continue without this capability.")
        if status == 404:
            raise NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi reported the requested object as not found")
        if status == 409:
            raise NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi reported a conflict (the instance may be busy or "
                               "cluster state may be changing)", "Retry later.")
        if status == 429:
            err = NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi rate-limited the request", "Retry later.")
            if method == "GET":
                raise _Retryable(err)
            raise err
        if status >= 500:
            err = NiFiMCPError(ErrorCode.QUERY_FAILED, f"NiFi returned a server error ({status})")
            if method == "GET" and status in (502, 503, 504):
                raise _Retryable(err)
            raise err
        raise NiFiMCPError(ErrorCode.QUERY_FAILED, f"NiFi returned HTTP {status}")


class _Retryable(Exception):
    def __init__(self, error: NiFiMCPError):
        super().__init__(error.message)
        self.error = error


class _AmbiguousSubmission(NiFiMCPError):
    """A POST timed out after it may have reached NiFi. Never retried."""

    def __init__(self, error: NiFiMCPError):
        super().__init__(ErrorCode.TIMEOUT, "submission timed out; NiFi may have created a request this server "
                                            "cannot identify, so it was not retried",
                         "NiFi expires abandoned requests on its own; retry with a narrower interval.")


AmbiguousSubmission = _AmbiguousSubmission
