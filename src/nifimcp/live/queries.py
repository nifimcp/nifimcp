"""Owned observation-request lifecycle (provenance queries and queue listings).

Only the exact create / poll / delete lifecycle is allowed. Every request this
server creates is recorded with its ID, kind, origin, identity fingerprint,
scope, node and creation time; only recorded requests are polled or deleted.
Cleanup runs in ``finally`` (shielded from cancellation) on success, error,
cancellation and timeout. A failed cleanup is reported as a gap. An ambiguous
POST timeout is never retried.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

import anyio

from ..errors import ErrorCode, NiFiMCPError
from ..util import iso, utc_now
from .http import UUID, AmbiguousSubmission, NiFiHTTP, Response

CLEANUP_TIMEOUT = 10.0


@dataclass
class OwnedRequest:
    request_id: str
    kind: str                      # "provenance" | "listing"
    origin: str
    identity_fingerprint: str
    scope_id: str
    node_id: str | None
    created_at: str
    connection_id: str | None = None
    state: str = "created"
    deleted: bool = False


@dataclass
class QueryOutcome:
    final: Response | None
    request: OwnedRequest | None
    gaps: list[dict] = field(default_factory=list)
    finished: bool = False


class QueryRegistry:
    def __init__(self, http: NiFiHTTP, max_active: int):
        self.http = http
        self._owned: dict[str, OwnedRequest] = {}
        self._slots = anyio.Semaphore(max_active)
        self.history: list[OwnedRequest] = []

    def owned(self, request_id: str, kind: str) -> OwnedRequest:
        req = self._owned.get(request_id)
        if req is None or req.kind != kind or req.origin != self.http.origin:
            raise NiFiMCPError(ErrorCode.OUT_OF_SCOPE, "observation request is not owned by this server")
        return req

    @property
    def active(self) -> list[OwnedRequest]:
        return [r for r in self._owned.values() if not r.deleted]

    def _register(self, kind: str, request_id: Any, scope_id: str, connection_id: str | None = None) -> OwnedRequest:
        if not isinstance(request_id, str) or not UUID.fullmatch(request_id):
            raise NiFiMCPError(ErrorCode.QUERY_FAILED, "NiFi returned an unexpected request identifier")
        req = OwnedRequest(request_id=request_id, kind=kind, origin=self.http.origin,
                           identity_fingerprint=self.http.identity_fingerprint, scope_id=scope_id, node_id=None,
                           created_at=iso(utc_now()), connection_id=connection_id)
        self._owned[request_id] = req
        self.history.append(req)
        return req

    async def run_provenance(self, *, scope_id: str, body: dict, deadline: float, poll_interval: float = 0.4) -> QueryOutcome:
        async with self._slots:
            outcome = QueryOutcome(final=None, request=None)
            try:
                try:
                    created = await self.http.call("provenance_submit", body=body)
                except AmbiguousSubmission:
                    outcome.gaps.append({"code": "QUERY_INCOMPLETE", "detail": (
                        "The provenance submission timed out after it may have reached NiFi. It was not retried, "
                        "and any request NiFi created is not owned by this server; NiFi expires it on its own.")})
                    raise
                req = self._register("provenance", (created.data.get("provenance") or {}).get("id"), scope_id)
                outcome.request = req
                current = created
                while not (current.data.get("provenance") or {}).get("finished"):
                    if anyio.current_time() > deadline:
                        outcome.gaps.append({"code": "QUERY_INCOMPLETE",
                                             "detail": "The provenance query did not finish within the tool's time budget."})
                        break
                    await anyio.sleep(poll_interval)
                    self.owned(req.request_id, "provenance")
                    current = await self.http.call("provenance_get", params={"id": req.request_id},
                                                   query={"summarize": "false", "incrementalResults": "false"})
                else:
                    outcome.finished = True
                req.state = "finished" if outcome.finished else "incomplete"
                outcome.final = current
                return outcome
            finally:
                if outcome.request is not None:
                    await self._cleanup(outcome, "provenance_delete", {"id": outcome.request.request_id})

    async def run_listing(self, *, scope_id: str, connection_id: str, deadline: float, poll_interval: float = 0.3) -> QueryOutcome:
        async with self._slots:
            outcome = QueryOutcome(final=None, request=None)
            try:
                try:
                    created = await self.http.call("listing_submit", params={"id": connection_id}, body={})
                except AmbiguousSubmission:
                    outcome.gaps.append({"code": "QUERY_INCOMPLETE", "detail": (
                        "The queue listing submission timed out after it may have reached NiFi and was not retried.")})
                    raise
                req = self._register("listing", (created.data.get("listingRequest") or {}).get("id"), scope_id,
                                     connection_id)
                outcome.request = req
                current = created
                while not (current.data.get("listingRequest") or {}).get("finished"):
                    if anyio.current_time() > deadline:
                        outcome.gaps.append({"code": "QUERY_INCOMPLETE",
                                             "detail": "The queue listing did not finish within the tool's time budget."})
                        break
                    await anyio.sleep(poll_interval)
                    self.owned(req.request_id, "listing")
                    current = await self.http.call("listing_get", params={"id": connection_id,
                                                                          "listing-request-id": req.request_id})
                else:
                    outcome.finished = True
                failure = (current.data.get("listingRequest") or {}).get("failureReason")
                if failure:
                    outcome.gaps.append({"code": "QUEUE_SAMPLE_FAILED", "detail": "NiFi reported the listing failed."})
                outcome.final = current
                return outcome
            finally:
                if outcome.request is not None:
                    await self._cleanup(outcome, "listing_delete",
                                        {"id": connection_id, "listing-request-id": outcome.request.request_id})

    async def _cleanup(self, outcome: QueryOutcome, endpoint: str, params: dict) -> None:
        req = outcome.request
        with anyio.CancelScope(shield=True):
            try:
                with anyio.fail_after(CLEANUP_TIMEOUT):
                    self.owned(req.request_id, req.kind)
                    await self.http.call(endpoint, params=params)
                req.deleted = True
                # NiFi 2.12.0: deleting a listing removes it; deleting a provenance query cancels it and
                # NiFi keeps the finished query until its own expiration (about 30 minutes).
                req.state = "deleted" if req.kind == "listing" else "delete_acknowledged"
            except (NiFiMCPError, TimeoutError) as exc:
                req.state = "cleanup_failed"
                outcome.gaps.append({"code": "CLEANUP_FAILED", "detail": (
                    f"The {req.kind} request {req.request_id} could not be deleted "
                    f"({getattr(exc, 'code', 'TIMEOUT')}); NiFi will expire it on its own.")})

    def report(self) -> list[dict]:
        return [{"request_id": r.request_id, "kind": r.kind, "scope_id": r.scope_id, "created_at": r.created_at,
                 "state": r.state, "deleted": r.deleted} for r in self.history[-50:]]


def deadline_after(seconds: float) -> float:
    return anyio.current_time() + seconds


def utc(ts: dt.datetime) -> str:
    return iso(ts)
