"""Audit log shipper: batch audit records and forward them to a SIEM sink.

Research note: production SIEM pipelines (Splunk HTTP Event Collector,
Elastic's Elasticsearch bulk API, Datadog log intake) accept events in
*batched* POSTs, not one-at-a-time. A shipper sits between the local audit
writer and the remote collector and owns three jobs:

* **Batching** — accumulate records until a size limit (``max_batch_size``)
  or an explicit flush; deliver exactly one sink call per batch. Small
  writes become large ones, and network round-trips become O(1) per batch.
* **At-least-once forward** — the sink reports per-delivery success; a
  failed batch stays in the *outbox* and is redelivered on the next
  ``flush()`` or via an explicit ``retry()``. Nothing is acknowledged
  until the host reports success, so records are never silently dropped.
* **Fail-closed batching** — every batch carries a ``sha256:`` digest over
  its canonical contents plus a monotonic batch id. The sink (and the
  audit trail) can verify the batch byte-for-byte on replay.

Batch ids are minted as ``batch-<n>`` (monotonic, no wall-clock). The sink
is host-injectable: ``sink(batch) -> bool``. The default sink accepts the
batch in memory so tests (and the self-check) run without a network.

Honest scope: this books *forwarding decisions*, not deliveries — a
``delivered`` batch means "the host sink reported success", never "the
SIEM actually indexed it". Ordering between retries is best-effort; the
host owns dedup at the collector (pairs with ``exactly_once`` if the
collector needs dedup bookkeeping). Batch payloads are host-reported; the
module pins what it was handed.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
AUDIT_SHIPPER_VERSION = "audit-shipper.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.audit-shipper.v1"

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "shipper-created",
    "enqueued",
    "batch-delivered",
    "batch-failed",
    "retried",
    "rejected",
)

#: Upper bound on one payload (1 MiB) — a guardrail against a runaway host.
_MAX_PAYLOAD_BYTES = 1024 * 1024


class AuditShipperError(Exception):
    """Base error for the audit shipper."""


class DuplicateEnqueueError(AuditShipperError):
    """Raised when the same record id is enqueued twice."""


class BatchError(AuditShipperError):
    """Raised for malformed batch operations."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditShipperError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise AuditShipperError(f"{name} must be non-negative")
    return value


def _check_record(record: Any) -> Mapping[str, Any]:
    if not isinstance(record, Mapping):
        raise AuditShipperError(f"record must be a mapping, got {type(record).__name__}")
    return record


def _canonicalize(obj: Any) -> Any:
    """Canonicalize a payload; fail closed on anything unrepresentable."""
    if obj is None or isinstance(obj, (bool, str)):
        return obj
    if isinstance(obj, int):
        if abs(obj) > 2 ** 53:
            raise AuditShipperError("int magnitude beyond 2**53 refused (JCS float-loss caveat)")
        return obj
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise AuditShipperError("NaN/inf refused")
        if obj.is_integer() and abs(obj) > 2 ** 53:
            raise AuditShipperError("integral float magnitude beyond 2**53 refused")
        return obj
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    if isinstance(obj, Mapping):
        for k in obj:
            if not isinstance(k, str) or not k:
                raise AuditShipperError(f"bad mapping key {k!r}")
        return {k: _canonicalize(obj[k]) for k in sorted(obj)}
    raise AuditShipperError(f"non-canonicalizable value of type {type(obj).__name__}")


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


@dataclass(frozen=True)
class QueuedRecord:
    """One enqueued audit record with its digest pin."""

    record_id: str
    payload: Any
    payload_digest: str
    seq: int
    version: str = AUDIT_SHIPPER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "payload": self.payload,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ShippedBatch:
    """A sealed batch handed to the sink."""

    batch_id: str
    record_ids: tuple[str, ...]
    payloads: tuple[Any, ...]
    batch_digest: str
    seq: int
    attempt: int
    version: str = AUDIT_SHIPPER_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the batch digest from its contents."""
        body = {
            "batch_id": self.batch_id,
            "payloads": [_canonicalize(p) for p in self.payloads],
            "record_ids": list(self.record_ids),
            "seq": self.seq,
            "version": self.version,
        }
        return _digest(body) == self.batch_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "record_ids": list(self.record_ids),
            "payloads": [p for p in self.payloads],
            "batch_digest": self.batch_digest,
            "seq": self.seq,
            "attempt": self.attempt,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ShipOutcome:
    """Result of one flush cycle."""

    batches_delivered: int
    records_delivered: int
    batches_failed: int
    records_pending: int
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "batches_delivered": self.batches_delivered,
            "records_delivered": self.records_delivered,
            "batches_failed": self.batches_failed,
            "records_pending": self.records_pending,
            "seq": self.seq,
        }


class AuditShipper:
    """Batches audit records and forwards them to a host sink.

    ``enqueue(record_id, payload, seq)`` stages a record. ``flush(seq)``
    seals everything pending into one ``ShippedBatch`` and hands it to
    ``sink``; a failed batch stays pending for ``retry()``. Both
    ``flush`` and ``retry`` return a ``ShipOutcome``.
    """

    def __init__(
        self,
        max_batch_size: int = 100,
        sink: Callable[[ShippedBatch], bool] | None = None,
    ) -> None:
        if isinstance(max_batch_size, bool) or not isinstance(max_batch_size, int):
            raise AuditShipperError("max_batch_size must be an int")
        if max_batch_size < 1:
            raise AuditShipperError("max_batch_size must be >= 1")
        if sink is not None and not callable(sink):
            raise AuditShipperError("sink must be callable")
        self._max_batch_size = max_batch_size
        self._sink: Callable[[ShippedBatch], bool] = sink or (lambda batch: True)
        self._lock = threading.RLock()
        self._pending: list[QueuedRecord] = []
        self._pending_ids: set[str] = set()
        self._batch_counter = 0
        self._delivered_batches = 0
        self._delivered_records = 0
        self._failed_batches = 0
        self._last_seq = -1

    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise AuditShipperError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def enqueue(self, record_id: Any, payload: Any, seq: Any) -> QueuedRecord:
        """Stage one audit record; returns its pinned receipt."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            if not isinstance(record_id, str) or not record_id:
                raise AuditShipperError(f"record_id must be a non-empty str, got {record_id!r}")
            if record_id in self._pending_ids:
                raise DuplicateEnqueueError(f"record_id {record_id!r} already enqueued")
            record = _check_record(payload)
            canonical = _canonicalize(dict(record))
            blob = jcs_canonical_json(canonical)
            if len(blob) > _MAX_PAYLOAD_BYTES:
                raise AuditShipperError("payload exceeds 1 MiB guardrail")
            digest = _digest(canonical)
            entry = QueuedRecord(
                record_id=record_id,
                payload=canonical,
                payload_digest=digest,
                seq=seq,
            )
            self._pending.append(entry)
            self._pending_ids.add(record_id)
            return entry

    def _seal_batch(self, seq: int, attempt: int) -> ShippedBatch | None:
        if not self._pending:
            return None
        self._batch_counter += 1
        batch_id = f"batch-{self._batch_counter}"
        chunk = self._pending[: self._max_batch_size]
        body = {
            "batch_id": batch_id,
            "payloads": [r.payload for r in chunk],
            "record_ids": [r.record_id for r in chunk],
            "seq": seq,
            "version": AUDIT_SHIPPER_VERSION,
        }
        digest = _digest(body)
        return ShippedBatch(
            batch_id=batch_id,
            record_ids=tuple(r.record_id for r in chunk),
            payloads=tuple(r.payload for r in chunk),
            batch_digest=digest,
            seq=seq,
            attempt=attempt,
        )

    def _drop_delivered(self, batch: ShippedBatch) -> None:
        delivered = set(batch.record_ids)
        self._pending = [r for r in self._pending if r.record_id not in delivered]
        self._pending_ids -= delivered

    def flush(self, seq: Any) -> ShipOutcome:
        """Seal pending records into one batch and deliver it.

        A failed delivery keeps the batch in the outbox (records are
        never acknowledged on failure). Idempotent no-op when empty.
        """
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            batch = self._seal_batch(seq, attempt=1)
            if batch is None:
                return ShipOutcome(0, 0, 0, 0, seq)
            ok = bool(self._sink(batch))
            if ok:
                self._drop_delivered(batch)
                self._delivered_batches += 1
                self._delivered_records += len(batch.record_ids)
                return ShipOutcome(1, len(batch.record_ids), 0, len(self._pending), seq)
            self._failed_batches += 1
            return ShipOutcome(0, 0, 1, len(self._pending), seq)

    def retry(self, seq: Any) -> ShipOutcome:
        """Re-attempt the oldest pending batch (at-least-once forward).

        Refused fail-closed when there is nothing to retry.
        """
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            if not self._pending:
                raise BatchError("retry with empty outbox refused")
            batch = self._seal_batch(seq, attempt=2)
            assert batch is not None
            ok = bool(self._sink(batch))
            if ok:
                self._drop_delivered(batch)
                self._delivered_batches += 1
                self._delivered_records += len(batch.record_ids)
                return ShipOutcome(1, len(batch.record_ids), 0, len(self._pending), seq)
            self._failed_batches += 1
            return ShipOutcome(0, 0, 1, len(self._pending), seq)

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def pending_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(r.record_id for r in self._pending)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "pending": len(self._pending),
                "delivered_batches": self._delivered_batches,
                "delivered_records": self._delivered_records,
                "failed_batches": self._failed_batches,
                "batches_sealed": self._batch_counter,
                "max_batch_size": self._max_batch_size,
            }


def audit_shipper_audit_event(kind: str, seq: int, **detail: Any) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for shipper activity."""
    if kind not in _AUDIT_KINDS:
        raise AuditShipperError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": AUDIT_SHIPPER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    event.update({k: _canonicalize(v) for k, v in detail.items()})
    return event


def main() -> None:
    """Self-check: enqueue, flush, failure, retry."""
    seen: list[ShippedBatch] = []
    failures = [True]

    def flaky(batch: ShippedBatch) -> bool:
        seen.append(batch)
        if failures[0]:
            failures[0] = False
            return False
        return True

    ship = AuditShipper(max_batch_size=2, sink=flaky)
    r1 = ship.enqueue("a-1", {"event": "granted", "seq": 0}, 0)
    assert r1.payload_digest.startswith("sha256:")
    ship.enqueue("a-2", {"event": "denied"}, 1)
    ship.enqueue("a-3", {"event": "granted"}, 2)

    out = ship.flush(3)
    assert out.batches_failed == 1 and out.records_pending == 3, out.as_dict()
    # Batching: max_batch_size=2 so only 2 records were in the failed batch.
    assert len(seen[0].record_ids) == 2
    assert seen[0].verify()

    out = ship.retry(4)
    assert out.batches_delivered == 1 and out.records_delivered == 2, out.as_dict()
    assert ship.pending_count() == 1
    assert ship.pending_ids() == ("a-3",)

    out = ship.flush(5)
    assert out.batches_delivered == 1 and out.records_delivered == 1
    assert ship.pending_count() == 0
    stats = ship.stats()
    assert stats["delivered_records"] == 3 and stats["failed_batches"] == 1
    print("audit-shipper OK: batch, flush, fail, retry, stats")


if __name__ == "__main__":
    main()
