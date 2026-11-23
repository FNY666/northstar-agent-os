"""Hinted handoff: Dynamo-style unavailable-owner write buffering.

Research motivation: in Dynamo (DeCandia et al. 2007), a write that
would normally go to a temporarily unavailable replica is buffered as
a *hint* by a healthy coordinator and handed to the owner later, once
the owner recovers. The write is never silently dropped and never
delivered twice -- it stays ``pending`` until a host reports it
``delivered`` or a logical TTL expires it.

Public API:

- ``HintedHandoff()`` -- mutable, RLock-guarded ledger.
  - ``store(hint_id, key, value, target_node, seq, ttl_seqs=100)`` ->
    frozen ``HintRecord``: books a hinted write for ``target_node``.
    ``ttl_seqs`` counts in ledger seqs, not wall-clock seconds.
  - ``deliver(hint_id, seq)`` -> frozen ``DeliveryRecord``: marks the
    hint delivered (the host declares the write reached the owner;
    this module cannot verify wire delivery).
  - ``expire(seq)`` -> frozen ``ExpireReport``: deterministic TTL
    sweep -- hints with ``expiry_seq <= seq`` flip to ``expired`` as
    data, never raised.
  - Views: ``hint(hint_id)``, ``hint_ids()``, ``pending()``,
    ``stats()``, ``audit_log()`` -- pure reads, consume no seq.

Expiry discipline: a hint stored at ledger seq ``S`` with
``ttl_seqs=T`` expires at ``expiry_seq = S + T``. ``deliver()`` at or
after ``expiry_seq`` is refused fail-closed (``ExpiredHintError``);
``expire()`` books the transition for every lapsed hint in one
record. Hint ids are never recycled, and a delivered or expired hint
can never be stored, delivered, or revived again.

Values are pinned by ``sha256:`` digest over a type-tagged canonical
encoding (bool is not int; ``|int| >= 2**53`` and non-finite floats
refused); raw values never cross the audit boundary.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* hints and *host-reported* deliveries;
  it performs no networking and cannot prove the owner received the
  write, nor that the owner was genuinely down.
- A ``delivered`` record means the host said the handoff succeeded --
  never wire truth.
- TTLs are logical seq counts; no timers fire here. If the caller
  never advances the ledger, nothing expires.
- Node ids are host-declared; this module cannot distinguish a
  recovered owner from a misspelled id.

Version pin: ``hinted-handoff.v1`` / schema pin
``northstar.hinted-handoff.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
HINTED_HANDOFF_VERSION = "hinted-handoff.v1"

#: Schema pin carried by records and audit events.
HINTED_HANDOFF_SCHEMA = "northstar.hinted-handoff.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_STORED = "hinted-handoff.stored"
KIND_DELIVERED = "hinted-handoff.delivered"
KIND_EXPIRED = "hinted-handoff.expired"
KIND_REJECTED = "hinted-handoff.rejected"
_KINDS = frozenset({KIND_STORED, KIND_DELIVERED, KIND_EXPIRED, KIND_REJECTED})

#: Fixed vocabulary for hint statuses.
STATUS_PENDING = "pending"
STATUS_DELIVERED = "delivered"
STATUS_EXPIRED = "expired"
_STATUSES = frozenset({STATUS_PENDING, STATUS_DELIVERED, STATUS_EXPIRED})

_MAX_INT = 2**53 - 1
_MAX_TTL = 2**53 - 1


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class HintedHandoffError(Exception):
    """Base class for all hinted-handoff errors."""


class BadHintError(HintedHandoffError):
    """hint_id or key is malformed."""


class DuplicateHintError(HintedHandoffError):
    """hint_id is already booked (or was retired)."""


class UnknownHintError(HintedHandoffError):
    """hint_id was never stored."""


class BadNodeError(HintedHandoffError):
    """target_node is malformed."""


class BadValueError(HintedHandoffError):
    """Value is not an encodable scalar (or is an unsafe number)."""


class BadTTLSError(HintedHandoffError):
    """ttl_seqs is not a positive int."""


class HintStateError(HintedHandoffError):
    """Hint is not pending (already delivered or expired)."""


class ExpiredHintError(HintedHandoffError):
    """Hint lapsed its TTL before delivery."""


class SeqOrderError(HintedHandoffError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_hint_id(hint_id: Any) -> str:
    if isinstance(hint_id, bool) or not isinstance(hint_id, str):
        raise BadHintError(f"hint_id must be str, got {type(hint_id).__name__}")
    if not hint_id.strip():
        raise BadHintError("hint_id must be non-empty")
    if len(hint_id) > 256:
        raise BadHintError("hint_id exceeds 256 chars")
    return hint_id


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadHintError(f"key must be str, got {type(key).__name__}")
    if not key.strip():
        raise BadHintError("key must be non-empty")
    if len(key) > 1024:
        raise BadHintError("key exceeds 1024 chars")
    return key


def _check_node(node: Any) -> str:
    if isinstance(node, bool) or not isinstance(node, str):
        raise BadNodeError(f"target_node must be str, got {type(node).__name__}")
    if not node.strip():
        raise BadNodeError("target_node must be non-empty")
    if len(node) > 256:
        raise BadNodeError("target_node exceeds 256 chars")
    return node


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    if seq > _MAX_INT:
        raise SeqOrderError("seq exceeds safe range")
    return seq


def _check_ttl(ttl: Any) -> int:
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise BadTTLSError(f"ttl_seqs must be int, got {type(ttl).__name__}")
    if ttl <= 0:
        raise BadTTLSError("ttl_seqs must be positive")
    if ttl > _MAX_TTL:
        raise BadTTLSError("ttl_seqs exceeds safe range")
    return ttl


def _value_type(value: Any) -> str:
    """Type tag for a storable scalar; raises BadValueError."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        if abs(value) > _MAX_INT:
            raise BadValueError("int value outside safe range")
        return "int"
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadValueError("non-finite float refused")
        return "float"
    if isinstance(value, str):
        if len(value) > 65536:
            raise BadValueError("str value exceeds 64 KiB")
        return "str"
    raise BadValueError(
        f"value must be str/int/float/bool/None, got {type(value).__name__}"
    )


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise HintedHandoffError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise HintedHandoffError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise HintedHandoffError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([HINTED_HANDOFF_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _value_digest(value: Any, vtype: str) -> str:
    return _pin("hinted-value", vtype, value)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HintRecord:
    """One booked hinted write.

    ``expiry_seq = stored_seq + ttl_seqs``; ``deliver()`` at or after
    ``expiry_seq`` is refused. ``verify()`` recomputes the digest pin.
    """

    hint_id: str
    key: str
    value_digest: str
    value_type: str
    target_node: str
    stored_seq: int
    expiry_seq: int
    status: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "store",
            self.hint_id,
            self.key,
            self.value_digest,
            self.value_type,
            self.target_node,
            self.stored_seq,
            self.expiry_seq,
            self.status,
            self.seq,
        )


@dataclass(frozen=True)
class DeliveryRecord:
    """One host-reported handoff delivery."""

    hint_id: str
    target_node: str
    stored_seq: int
    delivered_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "deliver",
            self.hint_id,
            self.target_node,
            self.stored_seq,
            self.delivered_seq,
            self.seq,
        )


@dataclass(frozen=True)
class ExpireReport:
    """One deterministic TTL sweep; expired ids are data, never raised."""

    seq: int
    expired_ids: Tuple[str, ...]
    expired_count: int
    pending_count: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the report is intact."""
        return self.digest == _pin(
            "expire", self.expired_ids, self.expired_count, self.pending_count,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def hinted_handoff_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for hinted handoff.

    Raw values never cross the audit boundary: ``detail`` may carry
    digests, ids, nodes and timestamps, never ``value``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise HintedHandoffError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise HintedHandoffError("detail must be a mapping")
    banned = {"value", "payload", "raw"}
    if any(k in detail for k in banned):
        raise HintedHandoffError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": HINTED_HANDOFF_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class HintedHandoff:
    """Dynamo-shaped hinted-handoff buffering (single-host bookkeeping).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). ``deliver()``
    books a host-declared delivery -- it is a ledger decision, never
    wire proof.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # hint_id -> record (frozen records; status transitions create the
        # next record in _history rather than mutating in place).
        self._hints: Dict[str, HintRecord] = {}
        self._retired: set = set()
        self._audit: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _consume_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(hinted_handoff_audit_event(kind, detail, seq))

    def _expired_at(self, hint: HintRecord, seq: int) -> bool:
        return seq >= hint.expiry_seq

    # -- public --------------------------------------------------------

    def store(
        self,
        hint_id: str,
        key: str,
        value: Any,
        target_node: str,
        seq: int,
        ttl_seqs: int = 100,
    ) -> HintRecord:
        """Book a hinted write for ``target_node``.

        The write stays ``pending`` until the host reports ``deliver()``
        or a TTL sweep expires it. Ids are never recycled: storing a
        hint_id that already exists raises ``DuplicateHintError``.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                hint_id = _check_hint_id(hint_id)
                key = _check_key(key)
                vtype = _value_type(value)
                node = _check_node(target_node)
                ttl = _check_ttl(ttl_seqs)
                if hint_id in self._hints or hint_id in self._retired:
                    raise DuplicateHintError(
                        f"hint_id {hint_id!r} already booked"
                    )
            except HintedHandoffError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "hint_id": hint_id if isinstance(hint_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            vdigest = _value_digest(value, vtype)
            expiry = seq + ttl
            record = HintRecord(
                hint_id=hint_id,
                key=key,
                value_digest=vdigest,
                value_type=vtype,
                target_node=node,
                stored_seq=seq,
                expiry_seq=expiry,
                status=STATUS_PENDING,
                seq=seq,
                digest="",
            )
            record = HintRecord(
                **{**record.__dict__,
                   "digest": _pin(
                       "store", hint_id, key, vdigest, vtype, node,
                       seq, expiry, STATUS_PENDING, seq,
                   )},
            )
            self._hints[hint_id] = record
            self._retired.add(hint_id)
            self._emit(
                KIND_STORED,
                {
                    "hint_id": hint_id,
                    "key": key,
                    "value_digest": vdigest,
                    "value_type": vtype,
                    "target_node": node,
                    "stored_seq": seq,
                    "expiry_seq": expiry,
                },
                seq,
            )
            return record

    def deliver(self, hint_id: str, seq: int) -> DeliveryRecord:
        """Mark a pending hint as delivered (host-reported).

        Refused fail-closed: unknown ids, hints already delivered or
        expired, and hints whose TTL lapsed at ``seq`` (``expired``
        hints go through ``expire()``, not delivery).
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                hint_id = _check_hint_id(hint_id)
                hint = self._hints.get(hint_id)
                if hint is None:
                    raise UnknownHintError(f"unknown hint_id {hint_id!r}")
                if hint.status == STATUS_DELIVERED:
                    raise HintStateError(
                        f"hint_id {hint_id!r} already delivered"
                    )
                if hint.status == STATUS_EXPIRED:
                    raise HintStateError(
                        f"hint_id {hint_id!r} already expired"
                    )
                if self._expired_at(hint, seq):
                    raise ExpiredHintError(
                        f"hint_id {hint_id!r} lapsed its TTL "
                        f"(expiry_seq {hint.expiry_seq}, seq {seq})"
                    )
            except HintedHandoffError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "hint_id": hint_id if isinstance(hint_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = DeliveryRecord(
                hint_id=hint_id,
                target_node=hint.target_node,
                stored_seq=hint.stored_seq,
                delivered_seq=seq,
                seq=seq,
                digest=_pin(
                    "deliver", hint_id, hint.target_node,
                    hint.stored_seq, seq, seq,
                ),
            )
            self._hints[hint_id] = HintRecord(
                **{**hint.__dict__, "status": STATUS_DELIVERED},
            )
            self._emit(
                KIND_DELIVERED,
                {
                    "hint_id": hint_id,
                    "target_node": hint.target_node,
                    "stored_seq": hint.stored_seq,
                    "delivered_seq": seq,
                },
                seq,
            )
            return record

    def expire(self, seq: int) -> ExpireReport:
        """Sweep TTLs: flip every pending hint with ``expiry_seq <= seq``.

        Expired ids are data, never raised; the returned report carries
        the sweep digest. This is the only mutation that transitions
        hints to ``expired``.
        """
        with self._lock:
            seq = self._consume_seq(seq)
            expired: List[str] = []
            for hint_id in sorted(self._hints):
                hint = self._hints[hint_id]
                if hint.status == STATUS_PENDING and self._expired_at(
                    hint, seq
                ):
                    expired.append(hint_id)
                    self._hints[hint_id] = HintRecord(
                        **{**hint.__dict__, "status": STATUS_EXPIRED},
                    )
            pending = sum(
                1 for h in self._hints.values()
                if h.status == STATUS_PENDING
            )
            report = ExpireReport(
                seq=seq,
                expired_ids=tuple(expired),
                expired_count=len(expired),
                pending_count=pending,
                digest=_pin(
                    "expire", tuple(expired), len(expired), pending, seq
                ),
            )
            for hint_id in expired:
                hint = self._hints[hint_id]
                self._emit(
                    KIND_EXPIRED,
                    {
                        "hint_id": hint_id,
                        "target_node": hint.target_node,
                        "stored_seq": hint.stored_seq,
                        "expiry_seq": hint.expiry_seq,
                    },
                    seq,
                )
            return report

    # -- views (pure; seq validated, never consumed) ---------------------

    def hint(self, hint_id: str) -> Optional[HintRecord]:
        """Return the current record for ``hint_id``, or None."""
        with self._lock:
            hint_id = _check_hint_id(hint_id)
            return self._hints.get(hint_id)

    def hint_ids(self) -> Tuple[str, ...]:
        """All booked hint ids, sorted."""
        with self._lock:
            return tuple(sorted(self._hints))

    def pending(self) -> Tuple[HintRecord, ...]:
        """All ``pending`` hint records, sorted by hint_id."""
        with self._lock:
            return tuple(
                self._hints[hint_id]
                for hint_id in sorted(self._hints)
                if self._hints[hint_id].status == STATUS_PENDING
            )

    def stats(self) -> Dict[str, Any]:
        """Ledger counts by status; pure read."""
        with self._lock:
            counts = {
                STATUS_PENDING: 0,
                STATUS_DELIVERED: 0,
                STATUS_EXPIRED: 0,
            }
            for hint in self._hints.values():
                counts[hint.status] += 1
            return {
                "schema": HINTED_HANDOFF_SCHEMA,
                "version": HINTED_HANDOFF_VERSION,
                "total": len(self._hints),
                **counts,
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Emitted audit rows, oldest first; pure read."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: store, deliver, expire, fail-closed."""
    ledger = HintedHandoff()
    record = ledger.store("h-1", "orders/42", "payload", "node-b", 1)
    assert record.status == STATUS_PENDING
    assert record.expiry_seq == 1 + 100
    assert record.verify()
    delivery = ledger.deliver("h-1", 2)
    assert delivery.verify()
    assert ledger.hint("h-1").status == STATUS_DELIVERED
    ledger.store("h-2", "orders/43", 7, "node-c", 3, ttl_seqs=2)
    report = ledger.expire(5)
    assert report.expired_ids == ("h-2",)
    assert report.verify()
    assert ledger.hint("h-2").status == STATUS_EXPIRED
    try:
        ledger.deliver("h-2", 6)
        raise AssertionError("delivering an expired hint must refuse")
    except HintStateError:
        pass
    # A lapsed-but-unswept hint is refused on delivery too.
    ledger.store("h-3", "orders/44", 8, "node-c", 8, ttl_seqs=2)
    try:
        ledger.deliver("h-3", 10)
        raise AssertionError("delivering a lapsed hint must refuse")
    except ExpiredHintError:
        pass
    ledger.expire(11)
    stats = ledger.stats()
    assert stats["pending"] == 0
    assert stats["delivered"] == 1
    assert stats["expired"] == 2
    kinds = [row["kind"] for row in ledger.audit_log()]
    assert KIND_STORED in kinds
    assert KIND_DELIVERED in kinds
    assert KIND_EXPIRED in kinds
    assert KIND_REJECTED in kinds
    print(
        "hinted-handoff OK: store, deliver, expire, fail-closed"
    )


if __name__ == "__main__":
    main()
