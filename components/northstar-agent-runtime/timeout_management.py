"""Timeout management — gRPC-shaped deadline propagation bookkeeping.

Research note (deadline propagation): gRPC propagates a deadline
(``grpc-timeout`` / ``grpc_deadline``) down the call tree so a single
client-side timeout bounds the whole distributed trace. The defining
rule is **tighten-only**: a child deadline may never exceed the
parent's deadline — it can only shorten it. Go's
``context.WithDeadline`` / ``context.WithTimeout`` implement the same
algebra, and distinguish ``DeadlineExceeded`` from explicit
``Canceled`` because the two demand different handling (retry vs
abort). This module takes that intersection for a deterministic
single-host ledger:

* **Logical-seq deadlines**: no wall-clock anywhere (that is the
  existing ``timeout_manager``'s job). A ``deadline()`` books
  ``expiry_seq = seq + ttl_seqs`` — the caller owns time as a
  strictly-increasing int.
* **Tighten-only propagation**: ``propagate()`` mints a child scope
  whose expiry can never exceed the parent's. A child asking for a
  looser deadline is refused fail-closed (its seq is still consumed,
  per batch discipline).
* **Explicit cancellation**: ``cancel()`` is terminal and distinct
  from expiry. Verdicts are data: ``expired(scope, seq)`` and
  ``remaining(scope, seq)`` are pure read views that never raise.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* deadlines and
*host-reported* propagation. It cannot measure elapsed time, fire a
deadline on its own, or force a child to respect the booked bound —
the host wires the frozen ``DeadlineRecord``s to its own scheduler
and treats ``expired``/``remaining`` as the authoritative verdicts.
GIGO on scope ids and parent links: the ledger pins what the host
declares.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Version pin for this module's record shape.
TIMEOUT_MANAGEMENT_VERSION = "timeout-management.v1"

#: Schema pin carried by records and audit events.
TIMEOUT_MANAGEMENT_SCHEMA = "northstar.timeout-management.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Maximum scope-id length (bookkeeping bound, not a protocol limit).
MAX_SCOPE_ID_LEN = 256

#: Audit event kinds.
KIND_DEADLINE_SET = "timeout.deadline-set"
KIND_PROPAGATED = "timeout.propagated"
KIND_CANCELLED = "timeout.cancelled"
KIND_REJECTED = "timeout.rejected"
_KINDS = (
    KIND_DEADLINE_SET,
    KIND_PROPAGATED,
    KIND_CANCELLED,
    KIND_REJECTED,
)

_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TimeoutManagementError(ValueError):
    """Base error for the timeout management ledger."""


class BadScopeError(TimeoutManagementError):
    """Malformed scope id."""


class DuplicateScopeError(TimeoutManagementError):
    """This scope id is already booked."""


class UnknownScopeError(TimeoutManagementError):
    """No scope with this id is booked."""


class CancelledScopeError(TimeoutManagementError):
    """This scope has been cancelled (terminal)."""


class BadDeadlineError(TimeoutManagementError):
    """Malformed ttl / expiry payload."""


class DeadlineExceedsParentError(TimeoutManagementError):
    """Child deadline would exceed the parent's (tighten-only rule)."""


class SeqOrderError(TimeoutManagementError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_scope_id(value: Any, name: str = "scope_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadScopeError(f"{name} must be a non-empty string")
    scope_id = value.strip()
    if len(scope_id) > MAX_SCOPE_ID_LEN:
        raise BadScopeError(f"{name} exceeds {MAX_SCOPE_ID_LEN} chars")
    if any(ch.isspace() for ch in scope_id):
        raise BadScopeError(f"{name} must not contain whitespace")
    return scope_id


def _check_ttl(value: Any, name: str = "ttl_seqs") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadDeadlineError(f"{name} must be an int")
    if value <= 0:
        raise BadDeadlineError(f"{name} must be positive")
    return value


def _canonical(value: Any) -> bytes:
    """Canonical encoding for digest pins (stdlib-only)."""
    try:
        from northstar_agent_runtime import canonical_json  # type: ignore

        payload = canonical_json.dumps(value)
        return payload.encode("utf-8")
    except Exception:
        import json

        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return payload.encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([TIMEOUT_MANAGEMENT_VERSION, *parts])
    ).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeadlineRecord:
    """One booked deadline (frozen). ``expiry_seq`` is a logical seq."""

    scope_id: str
    ttl_seqs: int
    expiry_seq: int
    parent_scope_id: str
    seq: int
    digest: str
    schema: str = TIMEOUT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "deadline",
            self.scope_id,
            self.ttl_seqs,
            self.expiry_seq,
            self.parent_scope_id,
            self.seq,
        )


@dataclass(frozen=True)
class PropagatedRecord:
    """One parent -> child deadline propagation (frozen, tighten-only)."""

    child_scope_id: str
    parent_scope_id: str
    expiry_seq: int
    tightened: bool
    seq: int
    digest: str
    schema: str = TIMEOUT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "propagate",
            self.child_scope_id,
            self.parent_scope_id,
            self.expiry_seq,
            self.tightened,
            self.seq,
        )


@dataclass(frozen=True)
class CancellationRecord:
    """One terminal cancellation (frozen). Distinct from expiry."""

    scope_id: str
    reason: str
    seq: int
    digest: str
    schema: str = TIMEOUT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "cancel", self.scope_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class RemainingReport:
    """One remaining-budget read (frozen). A pure view as data."""

    scope_id: str
    at_seq: int
    expiry_seq: int
    remaining: int
    expired: bool
    digest: str
    schema: str = TIMEOUT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "remaining",
            self.scope_id,
            self.at_seq,
            self.expiry_seq,
            self.remaining,
            self.expired,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def timeout_management_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the timeout manager."""
    if kind not in _KINDS:
        raise TimeoutManagementError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise TimeoutManagementError("detail must be a mapping")
    # Only ids, pins, and small ints cross the audit boundary.
    banned = {"reason_detail", "trace", "payload"}
    if any(k in detail for k in banned):
        raise TimeoutManagementError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": TIMEOUT_MANAGEMENT_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class TimeoutManagement:
    """Deterministic deadline-propagation ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._deadlines: Dict[str, DeadlineRecord] = {}
        self._propagations: Dict[str, PropagatedRecord] = {}
        self._cancellations: Dict[str, CancellationRecord] = {}
        self._cancelled: set = set()
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = -1

    # -- internals ------------------------------------------------------

    def _bump(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, error: Exception) -> None:
        self._audit.append(
            timeout_management_audit_event(
                KIND_REJECTED, {"reason": reason}, seq
            )
        )
        raise error

    # -- public API -----------------------------------------------------

    def deadline(
        self,
        scope_id: str,
        seq: int,
        ttl_seqs: int,
        parent_scope_id: str = "",
    ) -> DeadlineRecord:
        """Book a deadline for ``scope_id`` expiring at ``seq + ttl``.

        With ``parent_scope_id`` the tighten-only rule applies: the new
        expiry may not exceed the parent's expiry.
        """
        with self._lock:
            self._bump(seq)
            try:
                sid = _check_scope_id(scope_id)
                ttl = _check_ttl(ttl_seqs)
                parent = ""
                if parent_scope_id:
                    parent = _check_scope_id(parent_scope_id, "parent_scope_id")
            except TimeoutManagementError as exc:
                self._reject(seq, "bad-deadline-input", exc)
            if sid in self._deadlines:
                self._reject(
                    seq, "duplicate-scope", DuplicateScopeError(sid)
                )
            expiry = seq + ttl
            if parent:
                prec = self._deadlines.get(parent)
                if prec is None:
                    self._reject(
                        seq, "unknown-parent", UnknownScopeError(parent)
                    )
                if parent in self._cancelled:
                    self._reject(
                        seq, "parent-cancelled", CancelledScopeError(parent)
                    )
                if expiry > prec.expiry_seq:
                    self._reject(
                        seq,
                        "exceeds-parent",
                        DeadlineExceedsParentError(
                            f"child expiry {expiry} exceeds parent {prec.expiry_seq}"
                        ),
                    )
            record = DeadlineRecord(
                scope_id=sid,
                ttl_seqs=ttl,
                expiry_seq=expiry,
                parent_scope_id=parent,
                seq=seq,
                digest=_pin("deadline", sid, ttl, expiry, parent, seq),
            )
            self._deadlines[sid] = record
            self._audit.append(
                timeout_management_audit_event(
                    KIND_DEADLINE_SET,
                    {
                        "scope_id": sid,
                        "expiry_seq": expiry,
                        "parent_scope_id": parent,
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            return record

    def propagate(
        self,
        parent_scope_id: str,
        child_scope_id: str,
        seq: int,
        ttl_seqs: Optional[int] = None,
    ) -> PropagatedRecord:
        """Mint a child scope inheriting (and tightening) a parent deadline.

        The child expires at ``min(parent.expiry_seq, seq + ttl)``; with
        ``ttl_seqs=None`` it inherits the parent expiry verbatim
        (never tightened, never loosened).
        """
        with self._lock:
            self._bump(seq)
            try:
                parent = _check_scope_id(parent_scope_id, "parent_scope_id")
                child = _check_scope_id(child_scope_id, "child_scope_id")
                ttl = _check_ttl(ttl_seqs) if ttl_seqs is not None else None
            except TimeoutManagementError as exc:
                self._reject(seq, "bad-propagate-input", exc)
            prec = self._deadlines.get(parent)
            if prec is None:
                self._reject(seq, "unknown-parent", UnknownScopeError(parent))
            if parent in self._cancelled:
                self._reject(
                    seq, "parent-cancelled", CancelledScopeError(parent)
                )
            if child in self._deadlines or child in self._propagations:
                self._reject(
                    seq, "duplicate-scope", DuplicateScopeError(child)
                )
            child_expiry = prec.expiry_seq
            tightened = False
            if ttl is not None:
                wanted = seq + ttl
                if wanted < prec.expiry_seq:
                    child_expiry = wanted
                    tightened = True
                # wanted >= parent expiry: tighten-only clamps to parent.
            record = PropagatedRecord(
                child_scope_id=child,
                parent_scope_id=parent,
                expiry_seq=child_expiry,
                tightened=tightened,
                seq=seq,
                digest=_pin(
                    "propagate", child, parent, child_expiry, tightened, seq
                ),
            )
            self._propagations[child] = record
            self._deadlines[child] = DeadlineRecord(
                scope_id=child,
                ttl_seqs=child_expiry - seq if child_expiry > seq else 0,
                expiry_seq=child_expiry,
                parent_scope_id=parent,
                seq=seq,
                digest=_pin(
                    "deadline", child, 0, child_expiry, parent, seq
                ),
            )
            self._audit.append(
                timeout_management_audit_event(
                    KIND_PROPAGATED,
                    {
                        "child_scope_id": child,
                        "parent_scope_id": parent,
                        "expiry_seq": child_expiry,
                        "tightened": tightened,
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            return record

    def cancel(
        self, scope_id: str, seq: int, reason: str = ""
    ) -> CancellationRecord:
        """Terminally cancel a scope. Idempotent refusal on re-cancel."""
        with self._lock:
            self._bump(seq)
            try:
                sid = _check_scope_id(scope_id)
            except TimeoutManagementError as exc:
                self._reject(seq, "bad-cancel-input", exc)
            if sid not in self._deadlines:
                self._reject(seq, "unknown-scope", UnknownScopeError(sid))
            if sid in self._cancelled:
                self._reject(
                    seq, "already-cancelled", CancelledScopeError(sid)
                )
            record = CancellationRecord(
                scope_id=sid,
                reason=reason if isinstance(reason, str) else "",
                seq=seq,
                digest=_pin("cancel", sid, reason, seq),
            )
            self._cancellations[sid] = record
            self._cancelled.add(sid)
            self._audit.append(
                timeout_management_audit_event(
                    KIND_CANCELLED,
                    {"scope_id": sid, "digest": record.digest},
                    seq,
                )
            )
            return record

    def remaining(self, scope_id: str, seq: int) -> RemainingReport:
        """Pure read view: remaining logical seqs. Never raises on state."""
        with self._lock:
            _check_seq(seq, "at_seq")
            sid = _check_scope_id(scope_id)
            record = self._deadlines.get(sid)
            if record is None:
                raise UnknownScopeError(sid)
            rem = record.expiry_seq - seq
            expired = rem <= 0
            return RemainingReport(
                scope_id=sid,
                at_seq=seq,
                expiry_seq=record.expiry_seq,
                remaining=max(0, rem),
                expired=expired,
                digest=_pin(
                    "remaining", sid, seq, record.expiry_seq, max(0, rem), expired
                ),
            )

    def expired(self, scope_id: str, seq: int) -> bool:
        """Pure read view: is ``seq`` at/past the scope's expiry?"""
        return self.remaining(scope_id, seq).expired

    def cancelled(self, scope_id: str) -> bool:
        """Pure read view: has this scope been cancelled?"""
        with self._lock:
            sid = _check_scope_id(scope_id)
            return sid in self._cancelled

    # -- views ----------------------------------------------------------

    def scope(self, scope_id: str) -> DeadlineRecord:
        """Return the frozen deadline record for a scope."""
        with self._lock:
            sid = _check_scope_id(scope_id)
            record = self._deadlines.get(sid)
            if record is None:
                raise UnknownScopeError(sid)
            return record

    def propagation(self, child_scope_id: str) -> PropagatedRecord:
        """Return the frozen propagation record for a child scope."""
        with self._lock:
            cid = _check_scope_id(child_scope_id, "child_scope_id")
            record = self._propagations.get(cid)
            if record is None:
                raise UnknownScopeError(cid)
            return record

    def scope_ids(self) -> Tuple[str, ...]:
        """Sorted scope ids with booked deadlines."""
        with self._lock:
            return tuple(sorted(self._deadlines))

    def cancelled_ids(self) -> Tuple[str, ...]:
        """Sorted cancelled scope ids."""
        with self._lock:
            return tuple(sorted(self._cancelled))

    def stats(self) -> Dict[str, int]:
        """Ledger counts."""
        with self._lock:
            return {
                "scopes": len(self._deadlines),
                "propagations": len(self._propagations),
                "cancellations": len(self._cancellations),
                "audit_events": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events, oldest first."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """Full ledger snapshot as plain data."""
        with self._lock:
            return {
                "version": TIMEOUT_MANAGEMENT_VERSION,
                "schema": TIMEOUT_MANAGEMENT_SCHEMA,
                "scopes": {
                    sid: record.__dict__ for sid, record in self._deadlines.items()
                },
                "stats": self.stats(),
            }


def main() -> None:
    """Self-check: deadline, propagate, cancel, read views, audit."""
    tm = TimeoutManagement()
    root = tm.deadline("root", 1, 100)
    assert root.verify() and root.expiry_seq == 101
    child = tm.propagate("root", "child", 2, ttl_seqs=10)
    assert child.verify() and child.expiry_seq == 12 and child.tightened
    grandchild = tm.propagate("child", "grand", 3)
    assert grandchild.expiry_seq == 12 and not grandchild.tightened
    rep = tm.remaining("grand", 5)
    assert rep.verify() and rep.remaining == 7 and not rep.expired
    assert not tm.expired("grand", 5) and tm.expired("grand", 12)
    tm.cancel("child", 6, "user-request")
    assert tm.cancelled("child")
    try:
        tm.propagate("child", "x", 7)
        raise AssertionError("propagate from cancelled parent should fail")
    except CancelledScopeError:
        pass
    kinds = [e["kind"] for e in tm.audit_log()]
    assert KIND_DEADLINE_SET in kinds and KIND_REJECTED in kinds
    assert timeout_management_audit_event(
        KIND_PROPAGATED, {"child_scope_id": "c"}, 9
    )["schema"] == AUDIT_SCHEMA
    print(
        "timeout-management OK: deadline, propagate, cancel, remaining, "
        "expired, pins, audit"
    )


if __name__ == "__main__":
    main()
