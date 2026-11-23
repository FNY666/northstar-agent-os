"""Transaction manager: deterministic transaction lifecycle bookkeeping.

Research lineage: MVCC / snapshot isolation (Bernstein & Goodman 1983),
PostgreSQL-style transaction states. This is the *lifecycle* layer -- it
books the declared state transitions of named transactions
(``begin`` -> ``active`` -> ``committed`` / ``rolled-back``) without
storing any key/value data. Payload state lives in sibling layers such as
``mvcc_store`` (multi-version storage) and ``transactional_messaging``
(2PC vote bookkeeping); this module owns only the lifecycle ledger.

* **Ledger discipline** -- frozen dataclasses, caller-supplied strictly
  increasing int seqs, no wall-clock, RLock-guarded, fail-closed taxonomy.
  A failed mutation consumes its seq (batch-21 discipline) and books a
  ``transaction-manager.rejected`` audit row.
* **Terminal states** -- ``committed`` and ``rolled-back`` are terminal.
  A transaction id is never recycled; a retired id can never ``begin``
  again, so a host cannot silently resurrect a transaction.
* **Isolation vocabulary** -- ``begin`` pins an isolation level from
  ``read-committed`` / ``repeatable-read`` / ``serializable``. The level
  is booked as a declaration; this module enforces no isolation semantics
  (those belong to the store layer) -- it just guarantees the vocabulary
  is finite and pinned, so auditors see exactly what the host claimed.
* **Rollback reasons** -- pinned vocabulary ``explicit`` / ``conflict`` /
  ``timeout`` / ``aborted``. A ``rollback`` is a decision record, not
  proof the host undid anything.

Honest scope: this module books *declared* lifecycle transitions. It
cannot prove a committed transaction's writes reached any store, cannot
detect a host that lies about rollback, and performs no deadlock or
timeout detection. A ``CommitRecord`` is ledger truth ("the host declared
commit"), never wire truth.

Audit: ``transaction_manager_audit_event()`` builds ``audit.ndjson/1``
records of kinds ``txn-begun`` / ``txn-committed`` / ``txn-rolled-back`` /
``rejected``. Only ids, isolation levels, reasons and digests cross the
audit boundary -- never values or payloads.

Version pin: transaction-manager.v1
Schema pin: northstar.transaction-manager.v1
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Module version pin.
TRANSACTION_MANAGER_VERSION = "transaction-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.transaction-manager.v1"

#: Schema tag for audit records emitted by this module.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned isolation-level vocabulary.
ISOLATION_LEVELS = ("read-committed", "repeatable-read", "serializable")

#: Pinned rollback-reason vocabulary.
ROLLBACK_REASONS = ("explicit", "conflict", "timeout", "aborted")

#: Pinned transaction statuses.
STATUS_ACTIVE = "active"
STATUS_COMMITTED = "committed"
STATUS_ROLLED_BACK = "rolled-back"

_KINDS = ("txn-begun", "txn-committed", "txn-rolled-back", "rejected")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class TransactionManagerError(Exception):
    """Base class for transaction-manager errors."""


class BadTxnError(TransactionManagerError):
    """Malformed transaction id."""


class DuplicateTxnError(TransactionManagerError):
    """An active transaction with this id already exists."""


class RetiredTxnError(TransactionManagerError):
    """The id belonged to a transaction that already terminated."""


class UnknownTxnError(TransactionManagerError):
    """No transaction with this id has ever begun."""


class TerminalTxnError(TransactionManagerError):
    """The transaction is already committed or rolled back."""


class BadIsolationError(TransactionManagerError):
    """Isolation level outside the pinned vocabulary."""


class BadReasonError(TransactionManagerError):
    """Rollback reason outside the pinned vocabulary."""


class SeqOrderError(TransactionManagerError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(TransactionManagerError):
    """Unknown audit kind or banned keys in the audit detail."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    """Caller seqs are strictly increasing ints; bools are not ints."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_txn_id(txn_id: Any) -> str:
    if not isinstance(txn_id, str):
        raise BadTxnError(f"txn_id must be str, got {type(txn_id).__name__}")
    if not txn_id or not txn_id.strip():
        raise BadTxnError("txn_id must be non-empty")
    if len(txn_id) > 256:
        raise BadTxnError("txn_id exceeds 256 chars")
    if any(ch.isspace() for ch in txn_id):
        raise BadTxnError("txn_id must not contain whitespace")
    return txn_id


def _check_isolation(isolation: Any) -> str:
    if not isinstance(isolation, str) or isolation not in ISOLATION_LEVELS:
        raise BadIsolationError(
            f"isolation must be one of {ISOLATION_LEVELS}, got {isolation!r}"
        )
    return isolation


def _check_reason(reason: Any) -> str:
    if not isinstance(reason, str) or reason not in ROLLBACK_REASONS:
        raise BadReasonError(
            f"reason must be one of {ROLLBACK_REASONS}, got {reason!r}"
        )
    return reason


def _digest(parts: Tuple[Any, ...]) -> str:
    """Type-tagged sha256 digest pin over canonical JSON."""
    canonical = json.dumps(
        ["transaction-manager.v1", list(parts)],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def transaction_manager_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the transaction manager.

    ``detail`` may carry ids, statuses, isolation levels, reasons, digests
    and counts -- never ``payload``/``value``/``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"payload", "payload_bytes", "value", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": TRANSACTION_MANAGER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BeginRecord:
    """Frozen record of a ``begin()`` mutation."""

    txn_id: str
    isolation: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest((self.txn_id, self.isolation, self.seq))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "isolation": self.isolation,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CommitRecord:
    """Frozen record of a ``commit()`` mutation."""

    txn_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest((self.txn_id, "commit", self.seq))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RollbackRecord:
    """Frozen record of a ``rollback()`` mutation."""

    txn_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest((self.txn_id, self.reason, self.seq))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "txn_id": self.txn_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class TransactionManager:
    """Deterministic transaction lifecycle ledger.

    Thread-safe under an RLock. Caller seqs must strictly increase; a
    failed mutation consumes its seq and books ``transaction-manager.rejected``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._statuses: Dict[str, str] = {}
        self._begin_seqs: Dict[str, int] = {}
        self._isolation: Dict[str, str] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} does not strictly increase (last {self._seq})"
            )
        self._seq = seq
        return seq

    def _reject(self, seq: int, error: TransactionManagerError, **detail: Any) -> None:
        row = transaction_manager_audit_event(
            "rejected",
            {"error": type(error).__name__, **detail},
            seq,
        )
        self._audit.append(row)
        raise error

    # -- mutations --------------------------------------------------------

    def begin(self, txn_id: str, seq: int, isolation: str = "read-committed") -> BeginRecord:
        """Begin a transaction; returns a frozen ``BeginRecord``.

        Fail-closed: malformed ids, duplicate ids and retired ids are
        refused; failed mutations consume their seq.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                txn_id = _check_txn_id(txn_id)
                isolation = _check_isolation(isolation)
            except TransactionManagerError as exc:
                self._reject(seq, exc, txn_id=str(txn_id))
            status = self._statuses.get(txn_id)
            if status == STATUS_ACTIVE:
                self._reject(seq, DuplicateTxnError(f"txn {txn_id!r} already active"),
                             txn_id=txn_id)
            if status is not None:
                self._reject(seq, RetiredTxnError(f"txn {txn_id!r} already terminated"),
                             txn_id=txn_id)
            digest = _digest((txn_id, isolation, seq))
            record = BeginRecord(
                txn_id=txn_id, isolation=isolation, seq=seq, digest=digest
            )
            self._statuses[txn_id] = STATUS_ACTIVE
            self._begin_seqs[txn_id] = seq
            self._isolation[txn_id] = isolation
            self._audit.append(
                transaction_manager_audit_event(
                    "txn-begun",
                    {"txn_id": txn_id, "isolation": isolation, "digest": digest},
                    seq,
                )
            )
            return record

    def commit(self, txn_id: str, seq: int) -> CommitRecord:
        """Commit an active transaction; terminal, fail-closed.

        Unknown ids and already-terminated transactions are refused.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                txn_id = _check_txn_id(txn_id)
            except TransactionManagerError as exc:
                self._reject(seq, exc, txn_id=str(txn_id))
            status = self._statuses.get(txn_id)
            if status is None:
                self._reject(seq, UnknownTxnError(f"unknown txn {txn_id!r}"),
                             txn_id=txn_id)
            if status != STATUS_ACTIVE:
                self._reject(seq, TerminalTxnError(f"txn {txn_id!r} already {status}"),
                             txn_id=txn_id)
            digest = _digest((txn_id, "commit", seq))
            record = CommitRecord(txn_id=txn_id, seq=seq, digest=digest)
            self._statuses[txn_id] = STATUS_COMMITTED
            self._audit.append(
                transaction_manager_audit_event(
                    "txn-committed",
                    {"txn_id": txn_id, "digest": digest},
                    seq,
                )
            )
            return record

    def rollback(self, txn_id: str, seq: int, reason: str = "explicit") -> RollbackRecord:
        """Roll back an active transaction; terminal, fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                txn_id = _check_txn_id(txn_id)
                reason = _check_reason(reason)
            except TransactionManagerError as exc:
                self._reject(seq, exc, txn_id=str(txn_id))
            status = self._statuses.get(txn_id)
            if status is None:
                self._reject(seq, UnknownTxnError(f"unknown txn {txn_id!r}"),
                             txn_id=txn_id)
            if status != STATUS_ACTIVE:
                self._reject(seq, TerminalTxnError(f"txn {txn_id!r} already {status}"),
                             txn_id=txn_id)
            digest = _digest((txn_id, reason, seq))
            record = RollbackRecord(
                txn_id=txn_id, reason=reason, seq=seq, digest=digest
            )
            self._statuses[txn_id] = STATUS_ROLLED_BACK
            self._audit.append(
                transaction_manager_audit_event(
                    "txn-rolled-back",
                    {"txn_id": txn_id, "reason": reason, "digest": digest},
                    seq,
                )
            )
            return record

    # -- pure views (seq shape validated, never consumed) ------------------

    def status(self, txn_id: str, seq: int) -> Optional[str]:
        """Current status of a transaction (``active``/``committed``/
        ``rolled-back``/``None``); pure read view."""
        with self._lock:
            _check_seq(seq)
            return self._statuses.get(_check_txn_id(txn_id))

    def active_txn_ids(self) -> Tuple[str, ...]:
        """Sorted ids of currently active transactions."""
        with self._lock:
            return tuple(
                sorted(
                    txn_id
                    for txn_id, status in self._statuses.items()
                    if status == STATUS_ACTIVE
                )
            )

    def isolation_of(self, txn_id: str, seq: int) -> Optional[str]:
        """Isolation level declared at ``begin``; pure read view."""
        with self._lock:
            _check_seq(seq)
            return self._isolation.get(_check_txn_id(txn_id))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Aggregate counts; pure read view (seq shape validated)."""
        with self._lock:
            _check_seq(seq)
            counts = {
                STATUS_ACTIVE: 0,
                STATUS_COMMITTED: 0,
                STATUS_ROLLED_BACK: 0,
            }
            for status in self._statuses.values():
                counts[status] += 1
            return {
                "active": counts[STATUS_ACTIVE],
                "committed": counts[STATUS_COMMITTED],
                "rolled_back": counts[STATUS_ROLLED_BACK],
                "total": len(self._statuses),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Frozen tuple of audit rows; pure read."""
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def main() -> None:
    """Self-check: begin -> commit -> terminality, rollback path, fail-closed."""
    mgr = TransactionManager()
    rec = mgr.begin("txn-1", 1)
    assert rec.verify()
    mgr.commit("txn-1", 2)
    assert mgr.status("txn-1", 3) == STATUS_COMMITTED
    try:
        mgr.begin("txn-1", 4)
        raise AssertionError("retired id must be refused")
    except RetiredTxnError:
        pass
    mgr.begin("txn-2", 5, isolation="serializable")
    mgr.rollback("txn-2", 6, reason="conflict")
    assert mgr.status("txn-2", 7) == STATUS_ROLLED_BACK
    assert mgr.stats(8)["active"] == 0
    kinds = [row["kind"] for row in mgr.audit_log()]
    assert kinds == [
        "txn-begun",
        "txn-committed",
        "rejected",
        "txn-begun",
        "txn-rolled-back",
    ], kinds
    print("transaction-manager OK: begin, commit, rollback, terminality, fail-closed")


if __name__ == "__main__":
    main()
