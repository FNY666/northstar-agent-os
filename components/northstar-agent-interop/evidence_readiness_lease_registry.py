"""Persistent lifecycle registry for evidence-readiness leases.

This is a freshness/revocation ledger, not an authorization service.  It keeps
lease registration and revocation durable across restarts and uses same-host
flock to make first registration and revocation idempotent.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence_readiness_lease import EvidenceReadinessLease, LeaseError

SCHEMA = "northstar.readiness-lease-registry.v1"
META_SCHEMA = "northstar.readiness-lease-registry-meta.v1"
ZERO = "sha256:" + "0" * 64
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTIONS = frozenset({"registered", "revoked"})
_FIELDS = frozenset({
    "schema_version", "sequence", "action", "lease_digest", "plan_id",
    "decision_digest", "manifest_digest", "gate_digest", "issued_at",
    "expires_at", "previous_digest", "record_digest",
})


class LeaseRegistryError(ValueError):
    """Malformed, stale, tampered, or unavailable lease registry state."""


@dataclass(frozen=True)
class LeaseRegistryRecord:
    schema_version: str
    sequence: int
    action: str
    lease_digest: str
    plan_id: str
    decision_digest: str
    manifest_digest: str
    gate_digest: str
    issued_at: int
    expires_at: int
    previous_digest: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "action": self.action,
            "lease_digest": self.lease_digest,
            "plan_id": self.plan_id,
            "decision_digest": self.decision_digest,
            "manifest_digest": self.manifest_digest,
            "gate_digest": self.gate_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "previous_digest": self.previous_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "record_digest": self.record_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "LeaseRegistryRecord":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise LeaseRegistryError("lease record fields are invalid")
        if value["schema_version"] != SCHEMA or value["action"] not in _ACTIONS:
            raise LeaseRegistryError("lease record schema/action is invalid")
        sequence = value["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise LeaseRegistryError("lease record sequence is invalid")
        for field in ("lease_digest", "decision_digest", "manifest_digest", "gate_digest", "previous_digest", "record_digest"):
            _digest(value[field], field)
        for field in ("plan_id",):
            if not isinstance(value[field], str) or not value[field] or len(value[field]) > 256:
                raise LeaseRegistryError(f"{field} is invalid")
        issued, expires = value["issued_at"], value["expires_at"]
        if (not isinstance(issued, int) or isinstance(issued, bool)
                or not isinstance(expires, int) or isinstance(expires, bool)
                or expires <= issued):
            raise LeaseRegistryError("lease timing is invalid")
        record = cls(
            SCHEMA, sequence, value["action"], value["lease_digest"],
            value["plan_id"], value["decision_digest"], value["manifest_digest"],
            value["gate_digest"], issued, expires, value["previous_digest"],
            value["record_digest"],
        )
        if record.computed_digest != record.record_digest:
            raise LeaseRegistryError("lease record digest mismatch")
        return record

    @property
    def computed_digest(self) -> str:
        return _hash(b"northstar.readiness-lease-registry.v1\0", self.payload())


@dataclass(frozen=True)
class LeaseRegistryVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    lease_digest: str = ""
    execution_authorized: bool = False


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LeaseRegistryError("registry value is not canonical JSON") from exc


def _hash(prefix: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(prefix + _canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LeaseRegistryError(f"{field} is invalid")
    return value


class EvidenceReadinessLeaseRegistry:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "leases.jsonl"
        self.lock_path = self.root / "leases.lock"
        self.meta_path = self.root / "leases.meta"
        self._ensure_meta()

    def _write_meta(self, value: dict[str, Any]) -> None:
        fd, name = tempfile.mkstemp(prefix=".leases.meta.", dir=self.root, text=True)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.meta_path)
            descriptor = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _fresh_meta(self, sequence: int, head: str | None, started: bool) -> dict[str, Any]:
        return {
            "schema_version": META_SCHEMA,
            "history_started": started,
            "high_water": {"sequence": sequence, "head_digest": head},
        }

    def _ensure_meta(self) -> None:
        if self.meta_path.exists():
            _high_water, error = self._read_high_water()
            if error is not None:
                raise LeaseRegistryError("lease registry metadata is corrupt")
            return
        self._write_meta(self._fresh_meta(0, None, False))

    def _read_high_water(self) -> tuple[tuple[int, str | None] | None, str | None]:
        if not self.meta_path.exists():
            return None, "missing"
        try:
            value = json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None, "corrupt"
        if not isinstance(value, dict) or value.get("schema_version") != META_SCHEMA:
            return None, "invalid"
        if not isinstance(value.get("history_started"), bool):
            return None, "invalid"
        high_water = value.get("high_water")
        if not isinstance(high_water, dict) or set(high_water) != {"sequence", "head_digest"}:
            return None, "invalid"
        sequence = high_water["sequence"]
        head = high_water["head_digest"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            return None, "invalid"
        if sequence == 0:
            if head is not None:
                return None, "invalid"
        elif not isinstance(head, str) or _DIGEST.fullmatch(head) is None:
            return None, "invalid"
        return (sequence, head), None

    def _history_started(self) -> bool:
        high_water, error = self._read_high_water()
        if error == "missing":
            return False
        if error is not None:
            raise LeaseRegistryError("lease registry metadata is corrupt")
        return bool(high_water and high_water[0] > 0)

    def _read_state(self) -> tuple[list[LeaseRegistryRecord], bool, str | None]:
        """Return (records, repaired, error) with the high-water mark applied.

        A hash chain alone cannot detect a rollback: any prefix of it verifies.
        The mark is what makes a shortened log — for example one with the
        revocation removed — read as unverifiable instead of current.
        """
        records, error = self._read_records()
        if error is not None:
            if not self.path.exists() and not self.meta_path.exists():
                return [], False, None
            return records, False, error
        high_water, mark_error = self._read_high_water()
        if mark_error is not None or high_water is None:
            if not self.path.exists() and not self.meta_path.exists():
                return [], False, None
            return [], False, "high_water_" + str(mark_error)
        sequence, head = high_water
        if sequence > len(records):
            return [], False, "history_truncated"
        if sequence == len(records):
            if len(records) == 0:
                return records, False, None
            if records[-1].record_digest != head:
                return [], False, "high_water_mismatch"
            return records, False, None
        # The log is ahead of its mark: a crash between append and mark update.
        self._write_meta(self._fresh_meta(len(records), records[-1].record_digest, True))
        return records, True, None

    @contextmanager
    def _lock(self):
        with self.lock_path.open("a+") as handle:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read_records(self) -> tuple[list[LeaseRegistryRecord], str | None]:
        if not self.path.exists():
            return ([], "history_missing") if self._history_started() else ([], None)
        try:
            raw = self.path.read_bytes()
        except OSError:
            return [], "history_unreadable"
        lines = raw.split(b"\n")
        if not raw.endswith(b"\n"):
            lines = lines[:-1]
        records: list[LeaseRegistryRecord] = []
        previous = ZERO
        expected = 1
        for line in lines:
            if not line.strip():
                continue
            try:
                record = LeaseRegistryRecord.from_dict(json.loads(line.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError, LeaseRegistryError):
                return records, "history_corrupt"
            if record.sequence != expected or record.previous_digest != previous:
                return records, "chain_break"
            records.append(record)
            previous = record.record_digest
            expected += 1
        return records, None

    @property
    def records(self) -> list[LeaseRegistryRecord]:
        records, _repaired, error = self._read_state()
        if error is not None:
            raise LeaseRegistryError(error)
        return records

    def verify(self) -> LeaseRegistryVerdict:
        records, _repaired, error = self._read_state()
        if error is not None:
            return LeaseRegistryVerdict("unverifiable", (error,), "", False)
        return LeaseRegistryVerdict(
            "replayable", (), records[-1].record_digest if records else "", False,
        )

    def _append(self, records: list[LeaseRegistryRecord], action: str,
                lease: EvidenceReadinessLease) -> LeaseRegistryRecord:
        sequence = len(records) + 1
        previous = records[-1].record_digest if records else ZERO
        unsigned = LeaseRegistryRecord(
            SCHEMA, sequence, action, lease.lease_digest, lease.plan_id,
            lease.decision_digest, lease.manifest_digest, lease.gate_digest,
            lease.issued_at, lease.expires_at, previous, "",
        )
        record = LeaseRegistryRecord(
            unsigned.schema_version, unsigned.sequence, unsigned.action,
            unsigned.lease_digest, unsigned.plan_id, unsigned.decision_digest,
            unsigned.manifest_digest, unsigned.gate_digest, unsigned.issued_at,
            unsigned.expires_at, unsigned.previous_digest, unsigned.computed_digest,
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)
        self._write_meta(self._fresh_meta(len(records) + 1, record.record_digest, True))
        return record

    def register(self, lease: EvidenceReadinessLease) -> LeaseRegistryRecord:
        if not isinstance(lease, EvidenceReadinessLease):
            raise LeaseRegistryError("lease is invalid")
        try:
            lease = EvidenceReadinessLease.from_dict(lease.to_dict())
        except LeaseError as exc:
            raise LeaseRegistryError("lease is invalid") from exc
        with self._lock():
            records, _repaired, error = self._read_state()
            if error is not None:
                raise LeaseRegistryError(error)
            existing = [record for record in records if record.lease_digest == lease.lease_digest]
            if any(record.action == "revoked" for record in existing):
                raise LeaseRegistryError("lease is revoked")
            if existing:
                record = existing[0]
                if (record.plan_id, record.decision_digest, record.manifest_digest, record.gate_digest,
                        record.issued_at, record.expires_at) != (
                            lease.plan_id, lease.decision_digest, lease.manifest_digest,
                            lease.gate_digest, lease.issued_at, lease.expires_at):
                    raise LeaseRegistryError("lease registration conflicts")
                return record
            return self._append(records, "registered", lease)

    def revoke(self, lease_digest: str) -> LeaseRegistryRecord:
        _digest(lease_digest, "lease_digest")
        with self._lock():
            records, _repaired, error = self._read_state()
            if error is not None:
                raise LeaseRegistryError(error)
            matching = [record for record in records if record.lease_digest == lease_digest]
            if not matching:
                raise LeaseRegistryError("lease is unknown")
            if any(record.action == "revoked" for record in matching):
                raise LeaseRegistryError("lease is already revoked")
            source = next(record for record in reversed(matching) if record.action == "registered")
            lease = EvidenceReadinessLease(
                source.schema_version.replace("readiness-lease-registry", "evidence-readiness-lease"),
                source.plan_id, source.decision_digest, source.manifest_digest,
                source.gate_digest, source.issued_at, source.expires_at, False,
                source.lease_digest,
            )
            return self._append(records, "revoked", lease)

    def inspect(self, lease_digest: str, *, now: int) -> LeaseRegistryVerdict:
        _digest(lease_digest, "lease_digest")
        if not isinstance(now, int) or isinstance(now, bool):
            raise LeaseRegistryError("now is invalid")
        records, _repaired, error = self._read_state()
        if error is not None:
            return LeaseRegistryVerdict("unverifiable", (error,), lease_digest, False)
        matching = [record for record in records if record.lease_digest == lease_digest]
        if not matching:
            return LeaseRegistryVerdict("unknown", ("lease_unknown",), lease_digest, False)
        if any(record.action == "revoked" for record in matching):
            return LeaseRegistryVerdict("revoked", ("lease_revoked",), lease_digest, False)
        source = next(record for record in reversed(matching) if record.action == "registered")
        if now > source.expires_at:
            return LeaseRegistryVerdict("expired", ("lease_expired",), lease_digest, False)
        return LeaseRegistryVerdict("active", (), lease_digest, False)


__all__ = [
    "SCHEMA", "LeaseRegistryError", "LeaseRegistryRecord", "LeaseRegistryVerdict",
    "EvidenceReadinessLeaseRegistry",
]
