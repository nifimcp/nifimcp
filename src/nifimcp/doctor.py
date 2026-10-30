"""`nifimcp doctor`: check configuration, workspace and (live) connectivity without changing anything."""
from __future__ import annotations

import os
import stat
import sys

from . import __version__
from .config import OperatorConfig
from .errors import NiFiMCPError


def _check(results: list, name: str, ok: bool | None, detail: str) -> None:
    results.append({"check": name, "result": "PASS" if ok else ("WARN" if ok is None else "FAIL"), "detail": detail})


async def run_doctor(config: OperatorConfig) -> dict:
    results: list[dict] = []
    _check(results, "python", sys.version_info[:2] == (3, 12), f"Python {sys.version.split()[0]} (qualified: 3.12)")
    _check(results, "config", True, f"mode={config.mode}, telemetry=off, update checks=off")
    art = config.artifact_path
    try:
        from .artifacts import ArtifactStore
        ArtifactStore(art, config.retention_days)
        mode = stat.S_IMODE(os.stat(art).st_mode)
        _check(results, "artifact_dir", mode & 0o077 == 0, f"{art} permissions {oct(mode)} (expected 0700)")
    except OSError as exc:
        _check(results, "artifact_dir", False, f"cannot create or read artifact directory ({type(exc).__name__})")
    try:
        from .catalog import load_catalog
        _check(results, "catalog", True, f"pinned NiFi 2.12.0 catalog {load_catalog()['catalog_hash'][:16]}…")
    except Exception as exc:  # noqa: BLE001
        _check(results, "catalog", False, f"catalog integrity failed ({type(exc).__name__})")
    if config.mode == "live":
        from .live.source import LiveSource
        try:
            source = LiveSource(config)
        except NiFiMCPError as err:
            _check(results, "credentials", False, err.message)
            return _done(results, config)
        try:
            about = await source.about()
            _check(results, "tls_and_identity", True, f"connected to {config.live.origin} with verified TLS")
            _check(results, "version", about.get("version") == "2.12.0", f"NiFi {about.get('version')}")
            topo = await source.topology()
            _check(results, "topology", not topo["clustered"],
                   "standalone" if not topo["clustered"] else "clustered: live investigation blocked in this release")
            caps = await source.capabilities()
            perms = caps["permissions"]
            for scope, readable in perms["scope_read"].items():
                _check(results, f"scope:{scope}", readable is True, f"read access: {readable}")
            _check(results, "provenance_policy", True if perms["provenance_query"] else None,
                   "query provenance granted" if perms["provenance_query"] else perms["provenance_note"])
        except NiFiMCPError as err:
            _check(results, "live", False, f"{err.code.value}: {err.message} {err.next_step}")
        finally:
            await source.aclose()
    else:
        try:
            from .service import Session
            session = Session(config)
            _check(results, "sources", bool(session.source.scopes()),
                   f"{len(session.source.scopes())} scope(s) available; no network used")
        except NiFiMCPError as err:
            _check(results, "sources", False, f"{err.code.value}: {err.message}")
    return _done(results, config)


def _done(results: list, config: OperatorConfig) -> dict:
    status = "error" if any(r["result"] == "FAIL" for r in results) else "ok"
    return {"nifimcp": __version__, "mode": config.mode, "status": status, "checks": results}
