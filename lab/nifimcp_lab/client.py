"""Lab-only NiFi REST client (administrative identity, mutations allowed).

Construction verifies the lab boundary first. This client must never be
imported by the ``nifimcp`` runtime package.
"""
from __future__ import annotations

import json
import ssl
import time
from pathlib import Path
from typing import Any

import httpx2

from .boundary import LabBoundaryError, load_manifest, verify_lab_target

CLIENT_ID = "nifimcp-lab"


class LabHTTPError(RuntimeError):
    def __init__(self, status: int, method: str, path: str, detail: str):
        super().__init__(f"{method} {path} -> HTTP {status}: {detail[:300]}")
        self.status = status


def _ssl_context(ca: str, cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(cert, key)
    return ctx


class LabClient:
    def __init__(self, lab_dir: Path, identity: str = "admin", *, verify_boundary: bool = True):
        self.lab_dir = Path(lab_dir)
        self.manifest = load_manifest(self.lab_dir)
        if verify_boundary:
            self.boundary_facts = verify_lab_target(self.manifest)
        else:  # only used while bootstrap is still creating the manifest's container
            self.boundary_facts = {}
        ident = self.manifest["pki"]["identities"].get(identity)
        if not ident:
            raise LabBoundaryError(f"unknown lab identity: {identity}")
        self.identity = identity
        self.origin = self.manifest["origin"]
        self._client = httpx2.Client(
            base_url=self.origin + "/nifi-api",
            verify=_ssl_context(self.manifest["pki"]["ca_path"], ident["cert_path"], ident["key_path"]),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx2.Timeout(30.0),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ http
    def request(self, method: str, path: str, *, json_body: Any = None, params: dict | None = None,
                files: dict | None = None, data: dict | None = None, expected=(200, 201, 202)) -> Any:
        if not path.startswith("/") or "://" in path:
            raise LabBoundaryError("lab client accepts only API-relative paths")
        resp = self._client.request(method, path, json=json_body, params=params, files=files, data=data)
        if resp.status_code not in expected:
            raise LabHTTPError(resp.status_code, method, path, resp.text)
        if not resp.content:
            return {}
        ctype = resp.headers.get("content-type", "")
        if "json" in ctype:
            return resp.json()
        return resp.content

    def get(self, path: str, **kw) -> Any:
        return self.request("GET", path, **kw)

    # ------------------------------------------------------------- helpers
    def revision(self, entity: dict) -> dict:
        rev = dict(entity.get("revision") or {"version": 0})
        rev["clientId"] = CLIENT_ID
        return {"version": rev.get("version", 0), "clientId": CLIENT_ID}

    def root_id(self) -> str:
        return self.get("/flow/process-groups/root")["processGroupFlow"]["id"]

    def create_group(self, parent: str, name: str, x: float = 0, y: float = 0) -> dict:
        return self.request("POST", f"/process-groups/{parent}/process-groups", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID},
            "component": {"name": name, "position": {"x": x, "y": y}},
        })

    def processor_bundle(self, type_name: str) -> dict:
        types = self.get("/flow/processor-types", params={"type": type_name}).get("processorTypes") or []
        matches = [t for t in types if t.get("type") == type_name]
        if len(matches) != 1:
            raise RuntimeError(f"processor type not uniquely installed: {type_name}")
        return matches[0]["bundle"]

    def create_processor(self, group: str, type_name: str, name: str, *, x: float, y: float,
                         properties: dict | None = None, auto_terminate: list[str] | None = None,
                         scheduling_period: str = "1 sec") -> dict:
        return self.request("POST", f"/process-groups/{group}/processors", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID},
            "component": {
                "type": type_name, "bundle": self.processor_bundle(type_name), "name": name,
                "position": {"x": x, "y": y},
                "config": {
                    "properties": properties or {},
                    "autoTerminatedRelationships": auto_terminate or [],
                    "schedulingPeriod": scheduling_period,
                    "schedulingStrategy": "TIMER_DRIVEN",
                },
            },
        })

    def update_processor(self, processor_id: str, *, properties: dict | None = None,
                         auto_terminate: list[str] | None = None, name: str | None = None) -> dict:
        entity = self.get(f"/processors/{processor_id}")
        component: dict[str, Any] = {"id": processor_id, "config": {}}
        if properties is not None:
            component["config"]["properties"] = properties
        if auto_terminate is not None:
            component["config"]["autoTerminatedRelationships"] = auto_terminate
        if name is not None:
            component["name"] = name
        return self.request("PUT", f"/processors/{processor_id}", json_body={
            "revision": self.revision(entity), "component": component,
        })

    def create_port(self, group: str, kind: str, name: str, *, x: float, y: float) -> dict:
        path = "input-ports" if kind == "input" else "output-ports"
        return self.request("POST", f"/process-groups/{group}/{path}", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID},
            "component": {"name": name, "position": {"x": x, "y": y}},
        })

    def create_funnel(self, group: str, *, x: float, y: float) -> dict:
        return self.request("POST", f"/process-groups/{group}/funnels", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID},
            "component": {"position": {"x": x, "y": y}},
        })

    def connect(self, group: str, source: dict, destination: dict, relationships: list[str], *,
                name: str = "", object_threshold: int = 10000, size_threshold: str = "1 GB",
                expiration: str = "0 sec") -> dict:
        return self.request("POST", f"/process-groups/{group}/connections", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID},
            "component": {
                "name": name,
                "source": source, "destination": destination,
                "selectedRelationships": relationships,
                "backPressureObjectThreshold": object_threshold,
                "backPressureDataSizeThreshold": size_threshold,
                "flowFileExpiration": expiration,
            },
        })

    def set_run_state(self, kind: str, component_id: str, state: str) -> dict:
        base = {"processor": "processors", "input": "input-ports", "output": "output-ports"}[kind]
        entity = self.get(f"/{base}/{component_id}")
        return self.request("PUT", f"/{base}/{component_id}/run-status", json_body={
            "revision": self.revision(entity), "state": state, "disconnectedNodeAcknowledged": False,
        })

    def schedule_group(self, group_id: str, state: str) -> dict:
        return self.request("PUT", f"/flow/process-groups/{group_id}", json_body={
            "id": group_id, "state": state, "disconnectedNodeAcknowledged": False,
        })

    def wait(self, predicate, timeout: float = 60.0, interval: float = 0.5, what: str = "condition"):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = predicate()
            if last:
                return last
            time.sleep(interval)
        raise TimeoutError(f"timed out waiting for {what}")

    def connection_queue_count(self, connection_id: str) -> int:
        status = self.get(f"/flow/connections/{connection_id}/status")
        snap = status["connectionStatus"]["aggregateSnapshot"]
        return int(snap.get("flowFilesQueued", 0))

    def list_queue(self, connection_id: str, timeout: float = 30.0) -> list[dict]:
        req = self.request("POST", f"/flowfile-queues/{connection_id}/listing-requests")
        lid = req["listingRequest"]["id"]
        try:
            def done():
                cur = self.get(f"/flowfile-queues/{connection_id}/listing-requests/{lid}")
                return cur if cur["listingRequest"].get("finished") else None
            cur = self.wait(done, timeout=timeout, what="queue listing")
            return list(cur["listingRequest"].get("flowFileSummaries") or [])
        finally:
            try:
                self.request("DELETE", f"/flowfile-queues/{connection_id}/listing-requests/{lid}")
            except LabHTTPError:
                pass

    def flowfile_attributes(self, connection_id: str, flowfile_id: str) -> dict:
        ff = self.get(f"/flowfile-queues/{connection_id}/flowfiles/{flowfile_id}")
        return dict(ff["flowFile"].get("attributes") or {})

    def empty_queue(self, connection_id: str, timeout: float = 30.0) -> None:
        req = self.request("POST", f"/flowfile-queues/{connection_id}/drop-requests")
        rid = req["dropRequest"]["id"]
        try:
            self.wait(lambda: self.get(f"/flowfile-queues/{connection_id}/drop-requests/{rid}")["dropRequest"].get("finished"),
                      timeout=timeout, what="queue drop")
        finally:
            try:
                self.request("DELETE", f"/flowfile-queues/{connection_id}/drop-requests/{rid}")
            except LabHTTPError:
                pass

    def download_definition(self, group_id: str) -> bytes:
        resp = self._client.get(f"/process-groups/{group_id}/download",
                                params={"includeReferencedServices": "true"})
        if resp.status_code != 200:
            raise LabHTTPError(resp.status_code, "GET", "download", resp.text)
        return resp.content

    def upload_definition(self, parent_id: str, group_name: str, definition: bytes, *, x: float = 0, y: float = 0) -> dict:
        files = {"file": ("flow.json", definition, "application/json")}
        data = {"groupName": group_name, "positionX": str(x), "positionY": str(y),
                "clientId": CLIENT_ID, "disconnectedNodeAcknowledged": "false"}
        return self.request("POST", f"/process-groups/{parent_id}/process-groups/upload", files=files, data=data)

    def delete_group(self, group_id: str) -> None:
        entity = self.get(f"/process-groups/{group_id}")
        rev = entity["revision"]
        self.request("DELETE", f"/process-groups/{group_id}",
                     params={"version": rev.get("version", 0), "clientId": CLIENT_ID,
                             "disconnectedNodeAcknowledged": "false"})

    # ----------------------------------------------------------- tenants
    def create_user(self, identity: str) -> dict:
        return self.request("POST", "/tenants/users", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID}, "component": {"identity": identity},
        })

    def find_user(self, identity: str) -> dict | None:
        for user in self.get("/tenants/users").get("users") or []:
            if (user.get("component") or {}).get("identity") == identity:
                return user
        return None

    def grant(self, action: str, resource: str, user_id: str) -> dict:
        """Add ``user_id`` to the policy for (action, resource), creating it if needed."""
        try:
            policy = self.get(f"/policies/{action}{resource}")
            component = policy["component"]
            # NiFi may return an inherited policy; only reuse an exact match.
            if component.get("resource") != resource:
                raise LabHTTPError(404, "GET", "policy", "inherited")
            users = [{"id": u["id"]} for u in component.get("users") or []]
            if any(u["id"] == user_id for u in users):
                return policy
            users.append({"id": user_id})
            return self.request("PUT", f"/policies/{component['id']}", json_body={
                "revision": self.revision(policy),
                "component": {"id": component["id"], "users": users,
                              "userGroups": component.get("userGroups") or []},
            })
        except LabHTTPError as exc:
            if exc.status != 404:
                raise
        return self.request("POST", "/policies", json_body={
            "revision": {"version": 0, "clientId": CLIENT_ID},
            "component": {"action": action, "resource": resource, "users": [{"id": user_id}], "userGroups": []},
        })


def dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)
