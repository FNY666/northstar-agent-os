"""Change data capture: Debezium-shaped change-event bookkeeping.

Research motivation: Debezium captures row-level changes from a
source database's commit log (MySQL binlog, PostgreSQL logical
replication slots, ...) and streams them as structured *change
events*. Each event carries an ``op`` (``c`` = create, ``u`` =
update, ``d`` = delete, ``r`` = snapshot read), the row state before
(``before``) and after (``after``) the change, and source metadata.
Consumers track their position with *offsets* -- the logical log
position up to which events have been delivered and processed.

Public API:

- ``ChangeDataCapture()`` -- mutable, RLock-guarded ledger.
  - ``source(table_id, seq, connector="debezium")`` -> frozen
    ``SourceRecord``: registers a captured table/collection (the
    Debezium "table" behind a connector's topic).
  - ``capture(change_id, table_id, op, seq, before=None, after=None)``
    -> frozen ``ChangeRecord``: books one Debezium-envelope change
    event. ``op`` is pinned to ``c``/``u``/``d``/``r``; the
    before/after contract is enforced fail-closed (``c``/``r`` carry
    ``after`` only, ``d`` carries ``before`` only, ``u`` carries both).
    Payloads are pinned by ``sha256:`` digest -- raw row bytes never
    enter a record or the audit boundary.
  - ``emit(change_id, seq)`` -> frozen ``EmitRecord``: books the
    host-declared emission of the change to the sink (the Kafka
    "record produced" moment; this module cannot verify wire
    delivery). Unknown ids and double emits are refused fail-closed.
  - ``offset(table_id, seq)`` -> frozen ``OffsetReport``: pure read
    view of the replication position -- last captured/emitted ledger
    seqs, captured/emitted/pending counts, and the sorted pending
    change ids (the Debezium offset commit surface).
  - Views: ``source_rec(table_id)``, ``source_ids()``,
    ``change(change_id)``, ``change_ids()``,
    ``emission(change_id)``, ``pending(table_id=None)``,
    ``stats()``, ``audit_log()`` -- pure reads, consume no seq.

Offset discipline: ``offset()`` validates the ``seq`` shape but never
consumes it and writes no audit row -- it is a query, not a mutation.
A reported ``last_emitted_seq`` means the host declared those events
emitted; it is ledger truth, never wire truth.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* change events and *host-reported*
  emissions; it performs no database connection, reads no commit log,
  and produces no wire traffic.
- An ``emitted`` record means the host said the event reached the
  sink -- never wire truth, never consumer-commit proof.
- Row values are pinned by digest only; the module never sees, stores,
  or transmits the actual row contents. GIGO on the host.
- Op codes and offsets are logical; no timers, no poll loops, no
  rebalancing live here.

Version pin: ``change-data-capture.v1`` / schema pin
``northstar.change-data-capture.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CHANGE_DATA_CAPTURE_VERSION = "change-data-capture.v1"

#: Schema pin carried by records and audit events.
CHANGE_DATA_CAPTURE_SCHEMA = "northstar.change-data-capture.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_SOURCE_REGISTERED = "change-data-capture.source-registered"
KIND_CAPTURED = "change-data-capture.captured"
KIND_EMITTED = "change-data-capture.emitted"
KIND_REJECTED = "change-data-capture.rejected"
_KINDS = frozenset(
    {
        KIND_SOURCE_REGISTERED,
        KIND_CAPTURED,
        KIND_EMITTED,
        KIND_REJECTED,
    }
)

#: Debezium op codes (envelope semantics).
OP_CREATE = "c"  # insert: after only
OP_UPDATE = "u"  # update: before + after
OP_DELETE = "d"  # delete: before only
OP_READ = "r"  # snapshot read: after only
_OPS = frozenset({OP_CREATE, OP_UPDATE, OP_DELETE, OP_READ})
_OP_NAMES = {
    OP_CREATE: "create",
    OP_UPDATE: "update",
    OP_DELETE: "delete",
    OP_READ: "snapshot-read",
}

_MAX_INT = 2**53 - 1
_MAX_DEPTH = 16
_MAX_STR = 65536
_MAX_KEY = 1024


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ChangeDataCaptureError(Exception):
    """Base class for all change-data-capture errors."""


class BadTableError(ChangeDataCaptureError):
    """table_id is malformed."""


class DuplicateTableError(ChangeDataCaptureError):
    """table_id is already registered (ids are never recycled)."""


class UnknownTableError(ChangeDataCaptureError):
    """table_id was never registered."""


class BadChangeError(ChangeDataCaptureError):
    """change_id is malformed."""


class DuplicateChangeError(ChangeDataCaptureError):
    """change_id is already booked (ids are never recycled)."""


class UnknownChangeError(ChangeDataCaptureError):
    """change_id was never captured."""


class BadOpError(ChangeDataCaptureError):
    """op is not one of c/u/d/r."""


class OpEnvelopeError(ChangeDataCaptureError):
    """before/after violates the op's Debezium envelope contract."""


class BadPayloadError(ChangeDataCaptureError):
    """before/after is not an encodable row value."""


class BadConnectorError(ChangeDataCaptureError):
    """connector name is malformed."""


class ChangeStateError(ChangeDataCaptureError):
    """Change is not in the expected state (e.g. already emitted)."""


class SeqOrderError(ChangeDataCaptureError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(value: Any, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadChangeError(f"{label} must be str, got {type(value).__name__}")
    if not value.strip():
        raise BadChangeError(f"{label} must be non-empty")
    if len(value) > 256:
        raise BadChangeError(f"{label} exceeds 256 chars")
    return value


def _check_table_id(table_id: Any) -> str:
    if isinstance(table_id, bool) or not isinstance(table_id, str):
        raise BadTableError(
            f"table_id must be str, got {type(table_id).__name__}"
        )
    if not table_id.strip():
        raise BadTableError("table_id must be non-empty")
    if len(table_id) > 256:
        raise BadTableError("table_id exceeds 256 chars")
    return table_id


def _check_connector(connector: Any) -> str:
    if isinstance(connector, bool) or not isinstance(connector, str):
        raise BadConnectorError(
            f"connector must be str, got {type(connector).__name__}"
        )
    if not connector.strip():
        raise BadConnectorError("connector must be non-empty")
    if len(connector) > 128:
        raise BadConnectorError("connector exceeds 128 chars")
    return connector


def _check_op(op: Any) -> str:
    if isinstance(op, bool) or not isinstance(op, str):
        raise BadOpError(f"op must be str, got {type(op).__name__}")
    if op not in _OPS:
        raise BadOpError(
            f"op must be one of {sorted(_OPS)}, got {op!r}"
        )
    return op


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    if seq > _MAX_INT:
        raise SeqOrderError("seq exceeds safe range")
    return seq


def _check_row(value: Any, depth: int = 0, path: str = "row") -> None:
    """Validate a row value: scalar, or dict/list of rows."""
    if depth > _MAX_DEPTH:
        raise BadPayloadError(f"{path}: nesting exceeds {_MAX_DEPTH}")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_INT:
            raise BadPayloadError(f"{path}: int outside safe range")
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadPayloadError(f"{path}: non-finite float refused")
        return
    if isinstance(value, str):
        if len(value) > _MAX_STR:
            raise BadPayloadError(f"{path}: str exceeds 64 KiB")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, bool) or not isinstance(key, str):
                raise BadPayloadError(f"{path}: row key must be str")
            if not key or len(key) > _MAX_KEY:
                raise BadPayloadError(f"{path}: row key malformed")
            _check_row(item, depth + 1, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_row(item, depth + 1, f"{path}[{i}]")
        return
    raise BadPayloadError(
        f"{path}: row must be scalar/dict/list, got {type(value).__name__}"
    )


def _check_envelope(op: str, before: Any, after: Any) -> None:
    """Enforce the Debezium before/after contract for ``op``."""
    if op in (OP_CREATE, OP_READ):
        if before is not None:
            raise OpEnvelopeError(
                f"op {op!r} ({_OP_NAMES[op]}) must not carry before"
            )
        if after is None:
            raise OpEnvelopeError(
                f"op {op!r} ({_OP_NAMES[op]}) requires after"
            )
    elif op == OP_DELETE:
        if before is None:
            raise OpEnvelopeError("op 'd' (delete) requires before")
        if after is not None:
            raise OpEnvelopeError("op 'd' (delete) must not carry after")
    else:  # OP_UPDATE
        if before is None:
            raise OpEnvelopeError("op 'u' (update) requires before")
        if after is None:
            raise OpEnvelopeError("op 'u' (update) requires after")


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
                raise ChangeDataCaptureError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ChangeDataCaptureError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ChangeDataCaptureError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([CHANGE_DATA_CAPTURE_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _row_digest(value: Any) -> str:
    """Digest pin for a row value; ``""`` marks an absent row half."""
    if value is None:
        return ""
    return _pin("row", value)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRecord:
    """One registered captured table/collection.

    ``verify()`` recomputes the digest pin.
    """

    table_id: str
    connector: str
    registered_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "source", self.table_id, self.connector, self.registered_seq,
            self.seq,
        )


@dataclass(frozen=True)
class ChangeRecord:
    """One booked Debezium-envelope change event.

    ``before_digest``/``after_digest`` are ``""`` when the op carries
    no such half (see ``_check_envelope``). ``verify()`` recomputes
    the digest pin.
    """

    change_id: str
    table_id: str
    op: str
    before_digest: str
    after_digest: str
    captured_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "capture",
            self.change_id,
            self.table_id,
            self.op,
            self.before_digest,
            self.after_digest,
            self.captured_seq,
            self.seq,
        )


@dataclass(frozen=True)
class EmitRecord:
    """One host-declared emission of a captured change.

    ``verify()`` recomputes the digest pin.
    """

    change_id: str
    table_id: str
    op: str
    captured_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "emit",
            self.change_id,
            self.table_id,
            self.op,
            self.captured_seq,
            self.seq,
        )


@dataclass(frozen=True)
class OffsetReport:
    """Pure read view of a table's replication position.

    ``last_emitted_seq`` is the host-declared offset commit point;
    ``pending_ids`` are captured but unemitted changes in sorted
    order. ``verify()`` recomputes the digest pin.
    """

    table_id: str
    last_captured_seq: int
    last_emitted_seq: int
    captured_count: int
    emitted_count: int
    pending_count: int
    pending_ids: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the report is intact."""
        return self.digest == _pin(
            "offset",
            self.table_id,
            self.last_captured_seq,
            self.last_emitted_seq,
            self.captured_count,
            self.emitted_count,
            self.pending_count,
            self.pending_ids,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def change_data_capture_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for change data capture.

    Row contents never cross the audit boundary: ``detail`` may carry
    digests, ids, ops and counts, never ``before``, ``after``,
    ``value``, ``payload`` or ``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise ChangeDataCaptureError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise ChangeDataCaptureError("detail must be a mapping")
    banned = {"before", "after", "value", "payload", "raw"}
    if any(k in detail for k in banned):
        raise ChangeDataCaptureError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CHANGE_DATA_CAPTURE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class ChangeDataCapture:
    """Debezium-shaped change data capture (single-host bookkeeping).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). ``emit()`` books a
    host-declared emission -- it is a ledger decision, never wire
    proof.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # table_id -> SourceRecord; change_id -> ChangeRecord.
        self._sources: Dict[str, SourceRecord] = {}
        self._changes: Dict[str, ChangeRecord] = {}
        # change_id -> EmitRecord.
        self._emitted: Dict[str, EmitRecord] = {}
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
        self._audit.append(change_data_capture_audit_event(kind, detail, seq))

    # -- public --------------------------------------------------------

    def source(
        self,
        table_id: str,
        seq: int,
        connector: str = "debezium",
    ) -> SourceRecord:
        """Register a captured table/collection behind a connector.

        Ids are never recycled: re-registering a table raises
        ``DuplicateTableError`` fail-closed.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                table_id = _check_table_id(table_id)
                connector = _check_connector(connector)
                if table_id in self._sources or table_id in self._retired:
                    raise DuplicateTableError(
                        f"table_id {table_id!r} already registered"
                    )
            except ChangeDataCaptureError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "table_id": table_id
                            if isinstance(table_id, str)
                            else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = SourceRecord(
                table_id=table_id,
                connector=connector,
                registered_seq=seq,
                seq=seq,
                digest=_pin("source", table_id, connector, seq, seq),
            )
            self._sources[table_id] = record
            self._retired.add(table_id)
            self._emit(
                KIND_SOURCE_REGISTERED,
                {
                    "table_id": table_id,
                    "connector": connector,
                    "registered_seq": seq,
                },
                seq,
            )
            return record

    def capture(
        self,
        change_id: str,
        table_id: str,
        op: str,
        seq: int,
        before: Any = None,
        after: Any = None,
    ) -> ChangeRecord:
        """Book one Debezium-envelope change event.

        The op's before/after contract is enforced (``c``/``r`` carry
        ``after`` only, ``d`` carries ``before`` only, ``u`` carries
        both). Row halves are pinned by digest only; raw row bytes
        never enter the record.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                change_id = _check_id(change_id, "change_id")
                table_id = _check_table_id(table_id)
                op = _check_op(op)
                if table_id not in self._sources:
                    raise UnknownTableError(
                        f"table_id {table_id!r} not registered"
                    )
                if change_id in self._changes or change_id in self._retired:
                    raise DuplicateChangeError(
                        f"change_id {change_id!r} already booked"
                    )
                if before is not None:
                    _check_row(before)
                if after is not None:
                    _check_row(after)
                _check_envelope(op, before, after)
            except ChangeDataCaptureError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "change_id": change_id
                            if isinstance(change_id, str)
                            else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            before_digest = _row_digest(before)
            after_digest = _row_digest(after)
            record = ChangeRecord(
                change_id=change_id,
                table_id=table_id,
                op=op,
                before_digest=before_digest,
                after_digest=after_digest,
                captured_seq=seq,
                seq=seq,
                digest=_pin(
                    "capture",
                    change_id,
                    table_id,
                    op,
                    before_digest,
                    after_digest,
                    seq,
                    seq,
                ),
            )
            self._changes[change_id] = record
            self._retired.add(change_id)
            self._emit(
                KIND_CAPTURED,
                {
                    "change_id": change_id,
                    "table_id": table_id,
                    "op": op,
                    "op_name": _OP_NAMES[op],
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                    "captured_seq": seq,
                },
                seq,
            )
            return record

    def emit(self, change_id: str, seq: int) -> EmitRecord:
        """Mark a captured change as emitted (host-declared).

        Refused fail-closed: unknown change ids and changes already
        emitted.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                change_id = _check_id(change_id, "change_id")
                change = self._changes.get(change_id)
                if change is None:
                    raise UnknownChangeError(
                        f"change_id {change_id!r} was never captured"
                    )
                if change_id in self._emitted:
                    raise ChangeStateError(
                        f"change_id {change_id!r} already emitted"
                    )
            except ChangeDataCaptureError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "change_id": change_id
                            if isinstance(change_id, str)
                            else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = EmitRecord(
                change_id=change_id,
                table_id=change.table_id,
                op=change.op,
                captured_seq=change.captured_seq,
                seq=seq,
                digest=_pin(
                    "emit",
                    change_id,
                    change.table_id,
                    change.op,
                    change.captured_seq,
                    seq,
                ),
            )
            self._emitted[change_id] = record
            self._emit(
                KIND_EMITTED,
                {
                    "change_id": change_id,
                    "table_id": change.table_id,
                    "op": change.op,
                    "captured_seq": change.captured_seq,
                },
                seq,
            )
            return record

    def offset(self, table_id: str, seq: int) -> OffsetReport:
        """Report a table's replication position (pure read).

        ``seq`` is shape-validated but never consumed; no audit row is
        written. ``last_emitted_seq`` is the host-declared offset
        commit point.
        """
        with self._lock:
            _check_seq(seq)
            table_id = _check_table_id(table_id)
            if table_id not in self._sources:
                raise UnknownTableError(
                    f"table_id {table_id!r} not registered"
                )
            captured = [
                ch for ch in self._changes.values()
                if ch.table_id == table_id
            ]
            emitted = [
                self._emitted[ch.change_id]
                for ch in captured
                if ch.change_id in self._emitted
            ]
            pending_ids = tuple(
                sorted(
                    ch.change_id for ch in captured
                    if ch.change_id not in self._emitted
                )
            )
            last_captured = (
                max(ch.captured_seq for ch in captured) if captured else 0
            )
            last_emitted = max(e.seq for e in emitted) if emitted else 0
            return OffsetReport(
                table_id=table_id,
                last_captured_seq=last_captured,
                last_emitted_seq=last_emitted,
                captured_count=len(captured),
                emitted_count=len(emitted),
                pending_count=len(pending_ids),
                pending_ids=pending_ids,
                seq=seq,
                digest=_pin(
                    "offset",
                    table_id,
                    last_captured,
                    last_emitted,
                    len(captured),
                    len(emitted),
                    len(pending_ids),
                    pending_ids,
                    seq,
                ),
            )

    # -- views (pure reads; no seq consumed) ----------------------------

    def source_rec(self, table_id: str) -> Optional[SourceRecord]:
        """Return the registered source record, or None."""
        with self._lock:
            return self._sources.get(table_id)

    def source_ids(self) -> Tuple[str, ...]:
        """Registered table ids in sorted order."""
        with self._lock:
            return tuple(sorted(self._sources))

    def change(self, change_id: str) -> Optional[ChangeRecord]:
        """Return the booked change record, or None."""
        with self._lock:
            return self._changes.get(change_id)

    def change_ids(self) -> Tuple[str, ...]:
        """Captured change ids in sorted order."""
        with self._lock:
            return tuple(sorted(self._changes))

    def emission(self, change_id: str) -> Optional[EmitRecord]:
        """Return the emission record, or None when not emitted."""
        with self._lock:
            return self._emitted.get(change_id)

    def pending(self, table_id: Optional[str] = None) -> Tuple[str, ...]:
        """Captured but unemitted change ids in sorted order."""
        with self._lock:
            ids = (
                cid for cid in self._changes if cid not in self._emitted
            )
            if table_id is not None:
                ids = (
                    cid for cid in ids
                    if self._changes[cid].table_id == table_id
                )
            return tuple(sorted(ids))

    def stats(self) -> Dict[str, Any]:
        """Ledger counts; pure read."""
        with self._lock:
            return {
                "schema": CHANGE_DATA_CAPTURE_SCHEMA,
                "version": CHANGE_DATA_CAPTURE_VERSION,
                "sources": len(self._sources),
                "captured": len(self._changes),
                "emitted": len(self._emitted),
                "pending": len(self._changes) - len(self._emitted),
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
    """Deterministic self-check: source, capture, emit, offset."""
    ledger = ChangeDataCapture()
    src = ledger.source("db.orders", 1)
    assert src.table_id == "db.orders"
    assert src.connector == "debezium"
    assert src.verify()
    # c: after only.
    created = ledger.capture(
        "chg-1", "db.orders", "c", 2,
        after={"id": 1, "total": 9.5},
    )
    assert created.op == OP_CREATE
    assert created.before_digest == ""
    assert created.after_digest.startswith("sha256:")
    assert created.verify()
    emission = ledger.emit("chg-1", 3)
    assert emission.verify()
    assert ledger.emission("chg-1") is emission
    # u: before + after.
    ledger.capture(
        "chg-2", "db.orders", "u", 4,
        before={"id": 1, "total": 9.5},
        after={"id": 1, "total": 10.0},
    )
    off = ledger.offset("db.orders", 5)
    assert off.captured_count == 2
    assert off.emitted_count == 1
    assert off.pending_count == 1
    assert off.pending_ids == ("chg-2",)
    assert off.last_captured_seq == 4
    assert off.last_emitted_seq == 3
    assert off.verify()
    # offset() is a pure read: re-query at the same seq is fine.
    again = ledger.offset("db.orders", 5)
    assert again == off
    # Envelope contracts are enforced fail-closed.
    try:
        ledger.capture("chg-3", "db.orders", "c", 6,
                       before={"id": 1}, after={"id": 1})
        raise AssertionError("create with before must refuse")
    except OpEnvelopeError:
        pass
    try:
        ledger.capture("chg-4", "db.orders", "d", 7,
                       before={"id": 1}, after={"id": 1})
        raise AssertionError("delete with after must refuse")
    except OpEnvelopeError:
        pass
    # Double emit is refused.
    try:
        ledger.emit("chg-1", 8)
        raise AssertionError("double emit must refuse")
    except ChangeStateError:
        pass
    # Unknown table offset is refused.
    try:
        ledger.offset("db.missing", 8)
        raise AssertionError("offset on unknown table must refuse")
    except UnknownTableError:
        pass
    # Digest determinism across instances.
    twin = ChangeDataCapture()
    twin.source("db.orders", 1)
    twin_created = twin.capture(
        "chg-1", "db.orders", "c", 2,
        after={"id": 1, "total": 9.5},
    )
    assert twin_created.digest == created.digest
    # Tamper detection.
    assert not replace(created, op="d").verify()
    kinds = [row["kind"] for row in ledger.audit_log()]
    assert KIND_SOURCE_REGISTERED in kinds
    assert KIND_CAPTURED in kinds
    assert KIND_EMITTED in kinds
    assert KIND_REJECTED in kinds
    stats = ledger.stats()
    assert stats["sources"] == 1
    assert stats["captured"] == 2
    assert stats["emitted"] == 1
    assert stats["pending"] == 1
    print("change-data-capture OK: source, capture, emit, offset")


if __name__ == "__main__":
    main()
