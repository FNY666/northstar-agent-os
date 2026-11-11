"""Persistent, thread-safe network-session leases for the egress sidecar."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any


class LeaseTableError(RuntimeError):
    """The lease source of truth could not be read or durably updated."""


class LeaseTable:
    """Atomic JSON lease table. The on-disk table is the source of truth."""

    def __init__(self, path: str | Path, *, ttl_seconds: float = 300.0) -> None:
        self.path = Path(path)
        self.ttl_seconds = float(ttl_seconds)
        if self.ttl_seconds <= 0:
            raise ValueError("lease TTL must be positive")
        self._lock = threading.RLock()
        self._has_persisted = self.path.exists()
        if self.path.exists():
            self.read()

    @staticmethod
    def key(run_id: str, session_id: str, destination: str) -> str:
        return "\x1f".join((run_id, session_id, destination))

    def _read_unlocked(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            if self._has_persisted:
                raise LeaseTableError("cannot read lease table: file disappeared")
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LeaseTableError(f"cannot read lease table: {type(exc).__name__}") from exc
        if not isinstance(value, dict) or value.get("format") != "northstar.egress-leases/1":
            raise LeaseTableError("lease table has an invalid format")
        leases = value.get("leases")
        if not isinstance(leases, dict) or any(not isinstance(k, str) or not isinstance(v, dict) for k, v in leases.items()):
            raise LeaseTableError("lease table contains invalid records")
        required = {"lease_id", "run_id", "session_id", "destination", "granted_at", "expires_at",
                    "revocation_epoch", "status", "revoked_by"}
        for record in leases.values():
            if not required.issubset(record) or record["status"] not in {"active", "revoked", "expired"}:
                raise LeaseTableError("lease table contains an invalid lease")
        return {key: dict(record) for key, record in leases.items()}

    def read(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return self._read_unlocked()

    def _write_unlocked(self, leases: dict[str, dict[str, Any]]) -> None:
        temporary = self.path.with_name(f".{self.path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps({"format": "northstar.egress-leases/1", "leases": leases}, sort_keys=True) + "\n"
            with open(temporary, "x", encoding="utf-8") as handle:
                os.chmod(temporary, 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            self._has_persisted = True
            directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise LeaseTableError(f"cannot persist lease table: {type(exc).__name__}") from exc

    def mint(self, run_id: str, session_id: str, destination: str, *, now: float | None = None) -> dict[str, Any]:
        with self._lock:
            leases = self._read_unlocked()
            key = self.key(run_id, session_id, destination)
            existing = leases.get(key)
            instant = time.time() if now is None else float(now)
            if existing is not None:
                return dict(existing)
            record: dict[str, Any] = {
                "lease_id": "lease-" + secrets.token_hex(16), "run_id": run_id,
                "session_id": session_id, "destination": destination,
                "granted_at": instant, "expires_at": instant + self.ttl_seconds,
                "revocation_epoch": 0, "status": "active", "revoked_by": "",
            }
            leases[key] = record
            self._write_unlocked(leases)
            return dict(record)

    def revoke(self, lease_id: str, revoked_by: str) -> dict[str, Any]:
        with self._lock:
            leases = self._read_unlocked()
            match = next((record for record in leases.values() if record.get("lease_id") == lease_id), None)
            if match is None:
                raise KeyError(lease_id)
            if revoked_by == match["run_id"]:
                raise PermissionError("the lease-owning run cannot revoke its own network lease")
            if match["status"] != "revoked":
                match["status"] = "revoked"
                match["revoked_by"] = revoked_by
                match["revocation_epoch"] = int(match["revocation_epoch"]) + 1
                self._write_unlocked(leases)
            return dict(match)

    def expire(self, lease_id: str) -> dict[str, Any]:
        with self._lock:
            leases = self._read_unlocked()
            match = next((record for record in leases.values() if record.get("lease_id") == lease_id), None)
            if match is None:
                raise KeyError(lease_id)
            if match["status"] == "active":
                match["status"] = "expired"
                self._write_unlocked(leases)
            return dict(match)
