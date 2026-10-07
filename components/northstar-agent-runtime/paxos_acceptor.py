"""Paxos acceptor: promised-ballot and accepted-value ledger.

Research motivation: Paxos (Lamport 1998, "The Part-Time Parliament") is
the classic single-value consensus protocol. While ``paxos_interface``
pins the protocol's messages as mint/validate bookkeeping, this module is
the *acceptor role itself*: a stateful, deterministic single-host ledger
that books every prepare/accept decision the role makes, with caller
logical seqs, fail-closed input validation, and audit events.

Role:

- ``prepare(ballot, seq)`` -> frozen ``PromiseRecord``. The acceptor
  promises iff ``ballot >= promised_ballot`` (the ``>=`` makes a
  re-sent prepare for the *same* ballot idempotent, so a retried Phase 1a
  is not a policy violation). A granted promise carries the acceptor's
  last accepted ``(ballot, value_digest)`` pair, or ``(0, "")`` when it
  accepted nothing. A stale ballot (``ballot < promised_ballot``) is
  refused with the verdict booked **as data**, never raised.
- ``accept(ballot, value_digest, seq)`` -> frozen ``AcceptRecord``. The
  acceptor accepts iff ``ballot >= promised_ballot``; acceptance moves
  the promise up to ``ballot`` and records the pair. Values are pinned
  by ``sha256:`` digest only -- raw values never enter a record.
- ``learn(seq)`` -> frozen ``LearnReport``: a pure read view of what
  this acceptor would report to a learner (promised ballot and last
  accepted pair). Validates the seq shape, consumes nothing, writes no
  audit row.

Safety invariants enforced locally:

- Promised-ballot monotonicity: it only ever moves up.
- Failed mutations consume their seq and book an ``acceptor.rejected``
  audit row (batch-21 discipline); a rewound/non-increasing seq raises
  ``SeqOrderError`` without consuming.
- Policy refusals (stale ballot) are data, never errors. Malformed
  inputs (bad ballot, bad digest, bad seq) raise fail-closed.

Honest scope:

- This is single-node *role bookkeeping*, not a distributed protocol.
  There is no quorum here (see ``paxos_interface.Learner``), no
  network round-trips, no timers. A ``PromiseRecord`` means "this node
  booked the promise", never "the fleet saw it".
- The node never sees raw values: ``accept`` pins ``sha256:`` over
  canonical JSON and keeps only the digest. It cannot become a second
  exfiltration channel.
- Canonical JSON note: digests serialize with ``json.dumps`` sorted
  keys and compact separators when ``canonical_json`` is unavailable.
  Like every JSON canonicalizer (RFC 8785 included), integers outside
  +/-2**53 are serialized as IEEE 754 doubles and lose precision;
  digest pins are type-tagged (bool != int) and refuse |n| >= 2**53.
- All seqs are caller-supplied ints (logical clock); no wall-clock is
  read anywhere in this module.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # canonical_json is a sibling runtime module, not a dependency.
    from canonical_json import jcs_dumps as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback path
    _cj = None  # type: ignore

#: Module version pin.
PAXOS_ACCEPTOR_VERSION = "paxos-acceptor.v1"

#: Schema pin carried by records and audit events.
PAXOS_ACCEPTOR_SCHEMA = "northstar.paxos-acceptor.v1"

#: Audit envelope schema.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
EVENT_PROMISED = "acceptor.promised"
EVENT_PREPARE_REFUSED = "acceptor.prepare-refused"
EVENT_ACCEPTED = "acceptor.accepted"
EVENT_ACCEPT_REFUSED = "acceptor.accept-refused"
EVENT_REJECTED = "acceptor.rejected"

_EVENT_KINDS = frozenset(
    {
        EVENT_PROMISED,
        EVENT_PREPARE_REFUSED,
        EVENT_ACCEPTED,
        EVENT_ACCEPT_REFUSED,
        EVENT_REJECTED,
    }
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: Refusal reason vocabulary.
REASON_STALE_BALLOT = "stale-ballot"


class PaxosAcceptorError(Exception):
    """Base error for Paxos acceptor bookkeeping (fail-closed)."""


class BadAcceptorError(PaxosAcceptorError):
    """Raised when the acceptor id is malformed."""


class BadBallotError(PaxosAcceptorError):
    """Raised when a ballot number is malformed (not a positive int)."""


class BadDigestError(PaxosAcceptorError):
    """Raised when a value digest is not a ``sha256:`` + 64-hex pin."""


class SeqOrderError(PaxosAcceptorError):
    """Raised when a seq is not strictly greater than the last one."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_acceptor_id(value: object) -> str:
    """Validate an acceptor id: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise BadAcceptorError(
            f"acceptor_id must be a string, got {type(value).__name__}"
        )
    acceptor_id = value.strip()
    if not acceptor_id:
        raise BadAcceptorError("acceptor_id must be non-empty")
    return acceptor_id


def _check_ballot(value: object) -> int:
    """Validate a ballot number: positive int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadBallotError(f"ballot must be an int, got {type(value).__name__}")
    if value <= 0:
        raise BadBallotError("ballot must be positive")
    return value


def _check_digest(value: object) -> str:
    """Validate a value pin: ``sha256:`` + 64 lowercase hex."""
    if not isinstance(value, str):
        raise BadDigestError(f"digest must be a string, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise BadDigestError("digest must be 'sha256:' + 64 hex chars")
    body = value[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError("digest body must be lowercase hex")
    return value


def _check_seq(value: object) -> int:
    """Validate a caller-supplied logical seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError("seq must be non-negative")
    return value


def _canonical(payload: Any) -> bytes:
    """Canonical bytes for digest pinning (JCS when available)."""
    if _cj is not None:
        return _cj(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise PaxosAcceptorError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise PaxosAcceptorError("non-finite float refused")
            return {"t": "float", "v": v}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if v is None:
            return {"t": "null"}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[_tag(k), _tag(val)] for k, val in sorted(v.items(), key=lambda kv: str(kv[0]))]}
        raise PaxosAcceptorError(f"unpinable type: {type(v).__name__}")

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pin(payload: Any) -> str:
    """Domain-separated ``sha256:`` pin over canonical bytes."""
    return _DIGEST_PREFIX + hmac.new(
        b"", _canonical(payload), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromiseRecord:
    """One prepare attempt; the verdict is data, never raised."""

    acceptor_id: str
    ballot: int
    granted: bool
    reason: str  # "" when granted, pinned vocabulary otherwise
    promised_ballot: int  # acceptor state *after* this mutation
    accepted_ballot: int  # 0 when the acceptor accepted nothing
    accepted_digest: str  # "" when the acceptor accepted nothing
    seq: int
    digest: str

    def verify(self) -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "promise",
                    self.acceptor_id,
                    self.ballot,
                    self.granted,
                    self.reason,
                    self.promised_ballot,
                    self.accepted_ballot,
                    self.accepted_digest,
                    self.seq,
                ]
            ),
        )


@dataclass(frozen=True)
class AcceptRecord:
    """One accept attempt; the verdict is data, never raised."""

    acceptor_id: str
    ballot: int
    value_digest: str
    granted: bool
    reason: str  # "" when granted, pinned vocabulary otherwise
    promised_ballot: int  # acceptor state *after* this mutation
    accepted_ballot: int
    accepted_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "accept",
                    self.acceptor_id,
                    self.ballot,
                    self.value_digest,
                    self.granted,
                    self.reason,
                    self.promised_ballot,
                    self.accepted_ballot,
                    self.accepted_digest,
                    self.seq,
                ]
            ),
        )


@dataclass(frozen=True)
class LearnReport:
    """Pure read view of what this acceptor would report to a learner."""

    acceptor_id: str
    promised_ballot: int
    accepted_ballot: int  # 0 when the acceptor accepted nothing
    accepted_digest: str  # "" when the acceptor accepted nothing
    seq: int  # validated, never consumed
    digest: str

    def verify(self) -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "learn",
                    self.acceptor_id,
                    self.promised_ballot,
                    self.accepted_ballot,
                    self.accepted_digest,
                    self.seq,
                ]
            ),
        )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def paxos_acceptor_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the Paxos acceptor."""
    if kind not in _EVENT_KINDS:
        raise PaxosAcceptorError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    # Value digests are pins; raw values must never cross the audit boundary.
    banned = {"value", "payload", "data", "message"}
    if any(k in detail for k in banned):
        raise PaxosAcceptorError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "paxos_acceptor",
        "module_version": PAXOS_ACCEPTOR_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Acceptor
# ---------------------------------------------------------------------------


class PaxosAcceptor:
    """Stateful Paxos acceptor ledger: prepare / accept / learn.

    Deterministic single-host state machine: frozen records, caller int
    seqs strictly increasing, no wall-clock, RLock-guarded, fail-closed.
    """

    def __init__(self, acceptor_id: str) -> None:
        self._acceptor_id = _check_acceptor_id(acceptor_id)
        self._lock = threading.RLock()
        self._seq = 0
        self._promised_ballot = 0
        self._accepted_ballot = 0
        self._accepted_digest = ""
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _claim(self, seq: int) -> int:
        """Claim a fresh seq: strictly increasing; rewind raises bare."""
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} is not greater than last seq {self._seq}"
            )
        self._seq = seq
        return seq

    def _reject(self, seq: int, error: str) -> None:
        """Book a failed mutation (seq already claimed) as an audit row."""
        self._audit.append(
            paxos_acceptor_audit_event(
                EVENT_REJECTED, seq, acceptor_id=self._acceptor_id, error=error
            )
        )

    def _snapshot(self) -> tuple[int, int, str]:
        return (self._promised_ballot, self._accepted_ballot, self._accepted_digest)

    # -- role API ------------------------------------------------------

    def prepare(self, ballot: int, seq: int) -> PromiseRecord:
        """Book a prepare attempt; return the promise record.

        Granted iff ``ballot >= promised_ballot``; a stale ballot is
        refused with the verdict as data. Both paths consume the seq.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                ballot = _check_ballot(ballot)
            except PaxosAcceptorError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            if ballot >= self._promised_ballot:
                self._promised_ballot = ballot
                promised, aballot, adigest = self._snapshot()
                record = PromiseRecord(
                    acceptor_id=self._acceptor_id,
                    ballot=ballot,
                    granted=True,
                    reason="",
                    promised_ballot=promised,
                    accepted_ballot=aballot,
                    accepted_digest=adigest,
                    seq=seq,
                    digest=_pin(
                        [
                            "promise",
                            self._acceptor_id,
                            ballot,
                            True,
                            "",
                            promised,
                            aballot,
                            adigest,
                            seq,
                        ]
                    ),
                )
                self._audit.append(
                    paxos_acceptor_audit_event(
                        EVENT_PROMISED,
                        seq,
                        acceptor_id=self._acceptor_id,
                        ballot=ballot,
                    )
                )
                return record
            promised, aballot, adigest = self._snapshot()
            record = PromiseRecord(
                acceptor_id=self._acceptor_id,
                ballot=ballot,
                granted=False,
                reason=REASON_STALE_BALLOT,
                promised_ballot=promised,
                accepted_ballot=aballot,
                accepted_digest=adigest,
                seq=seq,
                digest=_pin(
                    [
                        "promise",
                        self._acceptor_id,
                        ballot,
                        False,
                        REASON_STALE_BALLOT,
                        promised,
                        aballot,
                        adigest,
                        seq,
                    ]
                ),
            )
            self._audit.append(
                paxos_acceptor_audit_event(
                    EVENT_PREPARE_REFUSED,
                    seq,
                    acceptor_id=self._acceptor_id,
                    ballot=ballot,
                    reason=REASON_STALE_BALLOT,
                )
            )
            return record

    def accept(self, ballot: int, value_digest: str, seq: int) -> AcceptRecord:
        """Book an accept attempt; return the accept record.

        Accepted iff ``ballot >= promised_ballot``; acceptance moves the
        promise up to ``ballot`` and records the pair. Values are digest
        pins only. A stale ballot is refused with the verdict as data.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                ballot = _check_ballot(ballot)
                value_digest = _check_digest(value_digest)
            except PaxosAcceptorError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            granted = ballot >= self._promised_ballot
            if granted:
                self._promised_ballot = ballot
                self._accepted_ballot = ballot
                self._accepted_digest = value_digest
            promised, aballot, adigest = self._snapshot()
            record = AcceptRecord(
                acceptor_id=self._acceptor_id,
                ballot=ballot,
                value_digest=value_digest,
                granted=granted,
                reason="" if granted else REASON_STALE_BALLOT,
                promised_ballot=promised,
                accepted_ballot=aballot,
                accepted_digest=adigest,
                seq=seq,
                digest=_pin(
                    [
                        "accept",
                        self._acceptor_id,
                        ballot,
                        value_digest,
                        granted,
                        "" if granted else REASON_STALE_BALLOT,
                        promised,
                        aballot,
                        adigest,
                        seq,
                    ]
                ),
            )
            self._audit.append(
                paxos_acceptor_audit_event(
                    EVENT_ACCEPTED if granted else EVENT_ACCEPT_REFUSED,
                    seq,
                    acceptor_id=self._acceptor_id,
                    ballot=ballot,
                    value_digest=value_digest,
                    **({} if granted else {"reason": REASON_STALE_BALLOT}),
                )
            )
            return record

    def learn(self, seq: int) -> LearnReport:
        """Pure read view of acceptor state for a learner.

        Validates the seq shape, consumes nothing, writes no audit row.
        """
        with self._lock:
            seq = _check_seq(seq)
            promised, aballot, adigest = self._snapshot()
            return LearnReport(
                acceptor_id=self._acceptor_id,
                promised_ballot=promised,
                accepted_ballot=aballot,
                accepted_digest=adigest,
                seq=seq,
                digest=_pin(
                    ["learn", self._acceptor_id, promised, aballot, adigest, seq]
                ),
            )

    # -- views ---------------------------------------------------------

    def promised_ballot(self) -> int:
        """Current promised ballot (pure read)."""
        with self._lock:
            return self._promised_ballot

    def audit_log(self) -> list[Mapping[str, Any]]:
        """Append-only audit rows (pure read)."""
        with self._lock:
            return list(self._audit)

    def stats(self) -> Mapping[str, Any]:
        """Pure read view of ledger counters."""
        with self._lock:
            return {
                "acceptor_id": self._acceptor_id,
                "promised_ballot": self._promised_ballot,
                "accepted_ballot": self._accepted_ballot,
                "has_accepted": self._accepted_ballot > 0,
                "last_seq": self._seq,
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: prepare, promise, accept, learn, pins, audit."""
    digest = _pin(["value", "fleet-kill"])
    acc = PaxosAcceptor("acc-1")
    p1 = acc.prepare(1, seq=1)
    assert p1.granted and p1.promised_ballot == 1
    assert p1.accepted_ballot == 0 and p1.verify()
    a1 = acc.accept(1, digest, seq=2)
    assert a1.granted and a1.accepted_digest == digest and a1.verify()
    p2 = acc.prepare(2, seq=3)  # higher ballot wins, carries last accepted
    assert p2.granted and p2.accepted_ballot == 1 and p2.accepted_digest == digest
    p3 = acc.prepare(1, seq=4)  # stale ballot refused as data
    assert not p3.granted and p3.reason == REASON_STALE_BALLOT and p3.verify()
    a2 = acc.accept(1, digest, seq=5)
    assert not a2.granted and a2.verify()
    rep = acc.learn(6)
    assert rep.promised_ballot == 2 and rep.accepted_ballot == 1 and rep.verify()
    kinds = [row["kind"] for row in acc.audit_log()]
    assert kinds == [
        EVENT_PROMISED,
        EVENT_ACCEPTED,
        EVENT_PROMISED,
        EVENT_PREPARE_REFUSED,
        EVENT_ACCEPT_REFUSED,
    ]
    try:
        paxos_acceptor_audit_event("nope", 1)
    except PaxosAcceptorError:
        pass
    else:  # pragma: no cover
        raise AssertionError("bad audit kind must raise")
    print("paxos-acceptor OK: prepare, promise, accept, learn, pins, audit")


if __name__ == "__main__":  # pragma: no cover
    main()
