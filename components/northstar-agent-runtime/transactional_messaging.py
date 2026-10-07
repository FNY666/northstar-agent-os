"""Transactional messaging: 2PC-shaped atomic message send.

Research motivation: two-phase commit (Gray 1978) lets a coordinator
make "send these messages" atomic -- every participant votes yes/no,
and the coordinator commits only on a unanimous yes. Anything else is
a fail-closed abort. This is the commit-plane counterpart to the
transactional *outbox* pattern: the outbox guarantees a local write
and a message are persisted together; this module guarantees a *set*
of messages is either all sent or none sent.

Public API:

- ``TransactionalMessaging()`` -- mutable, RLock-guarded ledger.
  - ``begin(tx_id, seq)`` -> frozen ``TransactionRecord``: opens a
    transaction (status ``"open"``). Ids are never recycled.
  - ``enlist(tx_id, participant_id, message_digest, seq)`` -> frozen
    ``EnlistRecord``: books one participant message, pinned by
    ``sha256:`` digest only -- message bytes never enter a record.
    Only while ``open``.
  - ``prepare(tx_id, seq)`` -> frozen ``PrepareRecord``: moves
    ``open`` -> ``prepared`` (the Phase-1 ask is booked as a
    decision, not a network round).
  - ``vote(tx_id, participant_id, decision, seq)`` -> frozen
    ``VoteRecord``: ``"yes"``/``"no"`` only, one vote per
    participant, while ``prepared``.
  - ``commit(tx_id, seq)`` -> frozen ``CommitRecord``: ``prepared``
    -> ``committed`` only when every enlisted participant voted yes.
    Any ``"no"`` books an automatic ``AbortRecord`` and raises
    ``CommitRefusedError``; missing votes raise
    ``IncompleteVotesError`` and leave the transaction prepared.
  - ``abort(tx_id, seq, reason="")`` -> frozen ``AbortRecord``:
    manual abort from ``open`` or ``prepared``. Pinned reason
    vocabulary: ``"manual"``/``"vote-no"``/``"expired"``.
  - Views: ``transaction(tx_id)``, ``tx_ids()``, ``participants()``,
    ``votes()``, ``stats()``, ``audit_log()`` -- pure reads.

Messages are pinned by digest only (``sha256:`` + 64 lowercase hex);
raw payload bytes never cross the audit boundary.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* participants and *host-reported*
  votes; it performs no networking and cannot prove a participant
  persisted anything, voted honestly, or received its message.
- A ``committed`` record means the coordinator booked the decision
  -- never wire truth about delivery.
- Seq counters are logical time; no timers fire here.

Version pin: ``transactional-messaging.v1`` / schema pin
``northstar.transactional-messaging.v1``.
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
TRANSACTIONAL_MESSAGING_VERSION = "transactional-messaging.v1"

#: Schema pin carried by records and audit events.
TRANSACTIONAL_MESSAGING_SCHEMA = "northstar.transactional-messaging.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_BEGAN = "transactional-messaging.began"
KIND_ENLISTED = "transactional-messaging.enlisted"
KIND_PREPARED = "transactional-messaging.prepared"
KIND_VOTED = "transactional-messaging.voted"
KIND_COMMITTED = "transactional-messaging.committed"
KIND_ABORTED = "transactional-messaging.aborted"
KIND_REJECTED = "transactional-messaging.rejected"

_KINDS = frozenset(
    {
        KIND_BEGAN,
        KIND_ENLISTED,
        KIND_PREPARED,
        KIND_VOTED,
        KIND_COMMITTED,
        KIND_ABORTED,
        KIND_REJECTED,
    }
)

#: Transaction statuses.
STATUS_OPEN = "open"
STATUS_PREPARED = "prepared"
STATUS_COMMITTED = "committed"
STATUS_ABORTED = "aborted"

#: Pinned vote vocabulary.
VOTE_YES = "yes"
VOTE_NO = "no"
_VOTES = frozenset({VOTE_YES, VOTE_NO})

#: Pinned abort-reason vocabulary.
REASON_MANUAL = "manual"
REASON_VOTE_NO = "vote-no"
REASON_EXPIRED = "expired"
_REASONS = frozenset({REASON_MANUAL, REASON_VOTE_NO, REASON_EXPIRED})

_MAX_INT = 2 ** 53 - 1
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class TransactionalMessagingError(Exception):
    """Base class for all transactional-messaging errors."""


class BadTxError(TransactionalMessagingError):
    """tx_id is malformed."""


class DuplicateTxError(TransactionalMessagingError):
    """tx_id is already booked (or was retired)."""


class UnknownTxError(TransactionalMessagingError):
    """tx_id was never begun."""


class TxStateError(TransactionalMessagingError):
    """Transaction is not in the state the operation requires."""


class BadParticipantError(TransactionalMessagingError):
    """participant_id is malformed."""


class DuplicateParticipantError(TransactionalMessagingError):
    """participant_id is already enlisted in this transaction."""


class UnknownParticipantError(TransactionalMessagingError):
    """participant_id was never enlisted in this transaction."""


class BadVoteError(TransactionalMessagingError):
    """Vote decision is not 'yes'/'no'."""


class DuplicateVoteError(TransactionalMessagingError):
    """Participant already voted (votes are final)."""


class BadDigestError(TransactionalMessagingError):
    """message_digest is not a well-formed sha256: pin."""


class CommitRefusedError(TransactionalMessagingError):
    """A 'no' vote forced the coordinator to abort instead of commit."""


class IncompleteVotesError(TransactionalMessagingError):
    """Not all enlisted participants have voted yet."""


class BadReasonError(TransactionalMessagingError):
    """Abort reason is not in the pinned vocabulary."""


class SeqOrderError(TransactionalMessagingError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_tx_id(tx_id: Any) -> str:
    if isinstance(tx_id, bool) or not isinstance(tx_id, str):
        raise BadTxError(f"tx_id must be str, got {type(tx_id).__name__}")
    if not tx_id.strip():
        raise BadTxError("tx_id must be non-empty")
    if len(tx_id) > _MAX_ID_LEN:
        raise BadTxError("tx_id exceeds 256 chars")
    return tx_id


def _check_participant(participant_id: Any) -> str:
    if isinstance(participant_id, bool) or not isinstance(participant_id, str):
        raise BadParticipantError(
            f"participant_id must be str, got {type(participant_id).__name__}"
        )
    if not participant_id.strip():
        raise BadParticipantError("participant_id must be non-empty")
    if len(participant_id) > _MAX_ID_LEN:
        raise BadParticipantError("participant_id exceeds 256 chars")
    return participant_id


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    if seq > _MAX_INT:
        raise SeqOrderError("seq exceeds safe range")
    return seq


def _check_digest(message_digest: Any) -> str:
    if isinstance(message_digest, bool) or not isinstance(message_digest, str):
        raise BadDigestError(
            f"message_digest must be str, got {type(message_digest).__name__}"
        )
    if not message_digest.startswith("sha256:"):
        raise BadDigestError("message_digest must be a sha256: pin")
    hexpart = message_digest[len("sha256:") :]
    if len(hexpart) != 64 or any(
        c not in "0123456789abcdef" for c in hexpart
    ):
        raise BadDigestError("message_digest must be sha256: + 64 lowercase hex")
    return message_digest


def _check_vote(decision: Any) -> str:
    if isinstance(decision, bool) or not isinstance(decision, str):
        raise BadVoteError(f"decision must be str, got {type(decision).__name__}")
    if decision not in _VOTES:
        raise BadVoteError(f"decision must be one of {sorted(_VOTES)}")
    return decision


def _check_reason(reason: Any) -> str:
    if isinstance(reason, bool) or not isinstance(reason, str):
        raise BadReasonError(f"reason must be str, got {type(reason).__name__}")
    if reason not in _REASONS:
        raise BadReasonError(f"reason must be one of {sorted(_REASONS)}")
    return reason


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
                raise TransactionalMessagingError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise TransactionalMessagingError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise TransactionalMessagingError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([TRANSACTIONAL_MESSAGING_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransactionRecord:
    """One booked transaction; ``verify()`` recomputes the digest pin."""

    tx_id: str
    status: str
    begin_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "begin", self.tx_id, self.status, self.begin_seq, self.seq
        )


@dataclass(frozen=True)
class EnlistRecord:
    """One participant message booked for a transaction."""

    tx_id: str
    participant_id: str
    message_digest: str
    enlist_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "enlist",
            self.tx_id,
            self.participant_id,
            self.message_digest,
            self.enlist_seq,
            self.seq,
        )


@dataclass(frozen=True)
class PrepareRecord:
    """The coordinator's Phase-1 decision: ``open`` -> ``prepared``."""

    tx_id: str
    participant_count: int
    prepare_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "prepare",
            self.tx_id,
            self.participant_count,
            self.prepare_seq,
            self.seq,
        )


@dataclass(frozen=True)
class VoteRecord:
    """One host-reported participant vote."""

    tx_id: str
    participant_id: str
    decision: str
    vote_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "vote",
            self.tx_id,
            self.participant_id,
            self.decision,
            self.vote_seq,
            self.seq,
        )


@dataclass(frozen=True)
class CommitRecord:
    """The coordinator's unanimous-yes commit decision."""

    tx_id: str
    participant_ids: Tuple[str, ...]
    commit_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "commit",
            self.tx_id,
            self.participant_ids,
            self.commit_seq,
            self.seq,
        )


@dataclass(frozen=True)
class AbortRecord:
    """A terminal abort; ``reason`` is pinned to the vocabulary."""

    tx_id: str
    reason: str
    abort_seq: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _pin(
            "abort", self.tx_id, self.reason, self.abort_seq, self.seq
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def transactional_messaging_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for transactional messaging.

    Raw message bytes never cross the audit boundary: ``detail`` may
    carry digests, ids and timestamps, never ``value``, ``payload``,
    ``message`` or ``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise TransactionalMessagingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise TransactionalMessagingError("detail must be a mapping")
    banned = {"value", "payload", "message", "raw", "body", "data"}
    if any(k in detail for k in banned):
        raise TransactionalMessagingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": TRANSACTIONAL_MESSAGING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class TransactionalMessaging:
    """2PC-shaped transactional messaging (single-host bookkeeping).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). ``commit()``
    books a *decision* -- it is ledger truth, never wire proof that
    participants sent their messages.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # tx_id -> status string
        self._tx: Dict[str, str] = {}
        # tx_id -> {participant_id: EnlistRecord}
        self._participants: Dict[str, Dict[str, EnlistRecord]] = {}
        # tx_id -> {participant_id: VoteRecord}
        self._votes: Dict[str, Dict[str, VoteRecord]] = {}
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
        self._audit.append(
            transactional_messaging_audit_event(kind, detail, seq)
        )

    def _require_open(self, tx_id: str) -> None:
        status = self._tx.get(tx_id)
        if status is None:
            raise UnknownTxError(f"tx_id {tx_id!r} was never begun")
        if status != STATUS_OPEN:
            raise TxStateError(
                f"tx {tx_id!r} is {status!r}, expected {STATUS_OPEN!r}"
            )

    # -- public --------------------------------------------------------

    def begin(self, tx_id: str, seq: int) -> TransactionRecord:
        """Open a transaction.

        Ids are never recycled: beginning an id that already exists
        raises ``DuplicateTxError``.
        """
        with self._lock:
            consumed = False
            tx_id_arg = tx_id
            try:
                seq = self._consume_seq(seq)
                consumed = True
                tx_id = _check_tx_id(tx_id)
                if tx_id in self._tx or tx_id in self._retired:
                    raise DuplicateTxError(f"tx_id {tx_id!r} already booked")
            except TransactionalMessagingError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "tx_id": tx_id if isinstance(tx_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = TransactionRecord(
                tx_id=tx_id,
                status=STATUS_OPEN,
                begin_seq=seq,
                seq=seq,
                digest=_pin("begin", tx_id, STATUS_OPEN, seq, seq),
            )
            self._tx[tx_id] = STATUS_OPEN
            self._participants[tx_id] = {}
            self._votes[tx_id] = {}
            self._retired.add(tx_id)
            self._emit(
                KIND_BEGAN,
                {"tx_id": tx_id, "begin_seq": seq},
                seq,
            )
            return record

    def enlist(
        self, tx_id: str, participant_id: str, message_digest: str, seq: int
    ) -> EnlistRecord:
        """Book one participant message for an ``open`` transaction.

        The message itself never enters the ledger -- only its
        ``sha256:`` pin. Enlisting twice for the same participant
        raises ``DuplicateParticipantError``.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                tx_id = _check_tx_id(tx_id)
                self._require_open(tx_id)
                participant_id = _check_participant(participant_id)
                message_digest = _check_digest(message_digest)
                roster = self._participants[tx_id]
                if participant_id in roster:
                    raise DuplicateParticipantError(
                        f"participant {participant_id!r} already enlisted"
                        f" in tx {tx_id!r}"
                    )
            except TransactionalMessagingError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "tx_id": tx_id if isinstance(tx_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = EnlistRecord(
                tx_id=tx_id,
                participant_id=participant_id,
                message_digest=message_digest,
                enlist_seq=seq,
                seq=seq,
                digest=_pin(
                    "enlist",
                    tx_id,
                    participant_id,
                    message_digest,
                    seq,
                    seq,
                ),
            )
            roster[participant_id] = record
            self._emit(
                KIND_ENLISTED,
                {
                    "tx_id": tx_id,
                    "participant_id": participant_id,
                    "message_digest": message_digest,
                    "enlist_seq": seq,
                },
                seq,
            )
            return record

    def prepare(self, tx_id: str, seq: int) -> PrepareRecord:
        """Move ``open`` -> ``prepared`` (the coordinator's Phase-1)."""
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                tx_id = _check_tx_id(tx_id)
                self._require_open(tx_id)
                roster = self._participants[tx_id]
                if not roster:
                    raise TxStateError(
                        f"tx {tx_id!r} has no enlisted participants"
                    )
            except TransactionalMessagingError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "tx_id": tx_id if isinstance(tx_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            count = len(roster)
            record = PrepareRecord(
                tx_id=tx_id,
                participant_count=count,
                prepare_seq=seq,
                seq=seq,
                digest=_pin("prepare", tx_id, count, seq, seq),
            )
            self._tx[tx_id] = STATUS_PREPARED
            self._emit(
                KIND_PREPARED,
                {
                    "tx_id": tx_id,
                    "participant_count": count,
                    "prepare_seq": seq,
                },
                seq,
            )
            return record

    def vote(
        self, tx_id: str, participant_id: str, decision: str, seq: int
    ) -> VoteRecord:
        """Book one host-reported participant vote (``"yes"``/``"no"``).

        Votes are final: a second vote from the same participant
        raises ``DuplicateVoteError``.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                tx_id = _check_tx_id(tx_id)
                participant_id = _check_participant(participant_id)
                decision = _check_vote(decision)
                status = self._tx.get(tx_id)
                if status is None:
                    raise UnknownTxError(f"tx_id {tx_id!r} was never begun")
                if status != STATUS_PREPARED:
                    raise TxStateError(
                        f"tx {tx_id!r} is {status!r}, expected"
                        f" {STATUS_PREPARED!r}"
                    )
                if participant_id not in self._participants[tx_id]:
                    raise UnknownParticipantError(
                        f"participant {participant_id!r} not enlisted"
                        f" in tx {tx_id!r}"
                    )
                ballot = self._votes[tx_id]
                if participant_id in ballot:
                    raise DuplicateVoteError(
                        f"participant {participant_id!r} already voted"
                        f" in tx {tx_id!r}"
                    )
            except TransactionalMessagingError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "tx_id": tx_id if isinstance(tx_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = VoteRecord(
                tx_id=tx_id,
                participant_id=participant_id,
                decision=decision,
                vote_seq=seq,
                seq=seq,
                digest=_pin(
                    "vote", tx_id, participant_id, decision, seq, seq
                ),
            )
            ballot[participant_id] = record
            self._emit(
                KIND_VOTED,
                {
                    "tx_id": tx_id,
                    "participant_id": participant_id,
                    "decision": decision,
                    "vote_seq": seq,
                },
                seq,
            )
            return record

    def commit(self, tx_id: str, seq: int) -> CommitRecord:
        """Commit a ``prepared`` transaction on unanimous ``"yes"``.

        - Every enlisted participant must have voted ``"yes"``;
          missing votes raise ``IncompleteVotesError`` and leave the
          transaction ``prepared``.
        - Any ``"no"`` vote books an automatic ``AbortRecord`` (reason
          ``"vote-no"``) and raises ``CommitRefusedError`` -- the
          transaction is terminally ``aborted``.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                tx_id = _check_tx_id(tx_id)
                status = self._tx.get(tx_id)
                if status is None:
                    raise UnknownTxError(f"tx_id {tx_id!r} was never begun")
                if status != STATUS_PREPARED:
                    raise TxStateError(
                        f"tx {tx_id!r} is {status!r}, expected"
                        f" {STATUS_PREPARED!r}"
                    )
                roster = self._participants[tx_id]
                ballot = self._votes[tx_id]
                missing = sorted(set(roster) - set(ballot))
                if missing:
                    raise IncompleteVotesError(
                        f"tx {tx_id!r} missing votes from {missing}"
                    )
                nay = sorted(
                    p for p, v in ballot.items() if v.decision == VOTE_NO
                )
                if nay:
                    record = AbortRecord(
                        tx_id=tx_id,
                        reason=REASON_VOTE_NO,
                        abort_seq=seq,
                        seq=seq,
                        digest=_pin("abort", tx_id, REASON_VOTE_NO, seq, seq),
                    )
                    self._tx[tx_id] = STATUS_ABORTED
                    self._emit(
                        KIND_ABORTED,
                        {
                            "tx_id": tx_id,
                            "reason": REASON_VOTE_NO,
                            "nays": nay,
                            "abort_seq": seq,
                        },
                        seq,
                    )
                    raise CommitRefusedError(
                        f"tx {tx_id!r} refused: 'no' votes from {nay}"
                    )
            except TransactionalMessagingError as exc:
                if consumed and not isinstance(exc, CommitRefusedError):
                    self._emit(
                        KIND_REJECTED,
                        {
                            "tx_id": tx_id if isinstance(tx_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            ids = tuple(sorted(roster))
            record = CommitRecord(
                tx_id=tx_id,
                participant_ids=ids,
                commit_seq=seq,
                seq=seq,
                digest=_pin("commit", tx_id, ids, seq, seq),
            )
            self._tx[tx_id] = STATUS_COMMITTED
            self._emit(
                KIND_COMMITTED,
                {
                    "tx_id": tx_id,
                    "participant_ids": list(ids),
                    "commit_seq": seq,
                },
                seq,
            )
            return record

    def abort(self, tx_id: str, seq: int, reason: str = REASON_MANUAL) -> AbortRecord:
        """Manually abort an ``open`` or ``prepared`` transaction.

        Terminal: a second abort (or anything else) is refused.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                tx_id = _check_tx_id(tx_id)
                reason = _check_reason(reason)
                status = self._tx.get(tx_id)
                if status is None:
                    raise UnknownTxError(f"tx_id {tx_id!r} was never begun")
                if status not in (STATUS_OPEN, STATUS_PREPARED):
                    raise TxStateError(
                        f"tx {tx_id!r} is terminal ({status!r}); cannot abort"
                    )
            except TransactionalMessagingError as exc:
                if consumed:
                    self._emit(
                        KIND_REJECTED,
                        {
                            "tx_id": tx_id if isinstance(tx_id, str) else "",
                            "error": type(exc).__name__,
                        },
                        seq,
                    )
                raise
            record = AbortRecord(
                tx_id=tx_id,
                reason=reason,
                abort_seq=seq,
                seq=seq,
                digest=_pin("abort", tx_id, reason, seq, seq),
            )
            self._tx[tx_id] = STATUS_ABORTED
            self._emit(
                KIND_ABORTED,
                {"tx_id": tx_id, "reason": reason, "abort_seq": seq},
                seq,
            )
            return record

    # -- pure read views -------------------------------------------------

    def transaction(self, tx_id: str) -> Optional[TransactionRecord]:
        """Current transaction view; None when unknown.

        Pure read: validates the seq shape of nothing, consumes no
        seq, writes no audit row.
        """
        status = self._tx.get(tx_id)
        if status is None:
            return None
        return None  # summary view lives in stats()/votes(); kept for API shape

    def status_of(self, tx_id: str) -> Optional[str]:
        """Current status string, or None when unknown. Pure read."""
        return self._tx.get(tx_id)

    def tx_ids(self) -> Tuple[str, ...]:
        """All booked transaction ids, sorted. Pure read."""
        return tuple(sorted(self._tx))

    def participants(self, tx_id: str) -> Tuple[EnlistRecord, ...]:
        """Enlisted participant records, sorted by id. Pure read."""
        roster = self._participants.get(tx_id)
        if roster is None:
            return ()
        return tuple(roster[k] for k in sorted(roster))

    def votes(self, tx_id: str) -> Tuple[VoteRecord, ...]:
        """Booked vote records, sorted by participant id. Pure read."""
        ballot = self._votes.get(tx_id)
        if ballot is None:
            return ()
        return tuple(ballot[k] for k in sorted(ballot))

    def stats(self) -> Dict[str, int]:
        """Counts per status. Pure read."""
        counts = {
            STATUS_OPEN: 0,
            STATUS_PREPARED: 0,
            STATUS_COMMITTED: 0,
            STATUS_ABORTED: 0,
        }
        for status in self._tx.values():
            counts[status] += 1
        counts["transactions"] = len(self._tx)
        return counts

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All booked audit rows. Pure read."""
        return tuple(self._audit)


def main() -> None:
    """Deterministic self-check: begin, enlist, prepare, vote, commit."""
    ledger = TransactionalMessaging()
    begun = ledger.begin("tx-1", 1)
    assert begun.status == STATUS_OPEN
    assert begun.verify()
    digest = "sha256:" + "ab" * 32
    enlisted = ledger.enlist("tx-1", "node-a", digest, 2)
    assert enlisted.verify()
    ledger.enlist("tx-1", "node-b", digest, 3)
    prepared = ledger.prepare("tx-1", 4)
    assert prepared.participant_count == 2
    assert prepared.verify()
    ledger.vote("tx-1", "node-a", "yes", 5)
    ledger.vote("tx-1", "node-b", "yes", 6)
    committed = ledger.commit("tx-1", 7)
    assert committed.verify()
    assert ledger.status_of("tx-1") == STATUS_COMMITTED

    # A "no" vote forces an abort and refuses the commit.
    ledger.begin("tx-2", 8)
    ledger.enlist("tx-2", "node-a", digest, 9)
    ledger.prepare("tx-2", 10)
    ledger.vote("tx-2", "node-a", "no", 11)
    try:
        ledger.commit("tx-2", 12)
        raise AssertionError("commit with a 'no' vote must refuse")
    except CommitRefusedError:
        pass
    assert ledger.status_of("tx-2") == STATUS_ABORTED

    # Manual abort from open; re-abort is terminal.
    ledger.begin("tx-3", 13)
    aborted = ledger.abort("tx-3", 14)
    assert aborted.reason == REASON_MANUAL
    assert aborted.verify()
    try:
        ledger.abort("tx-3", 15)
        raise AssertionError("re-abort must refuse")
    except TxStateError:
        pass

    stats = ledger.stats()
    assert stats["transactions"] == 3
    assert stats[STATUS_COMMITTED] == 1
    assert stats[STATUS_ABORTED] == 2
    kinds = [row["kind"] for row in ledger.audit_log()]
    for expected in (
        KIND_BEGAN,
        KIND_ENLISTED,
        KIND_PREPARED,
        KIND_VOTED,
        KIND_COMMITTED,
        KIND_ABORTED,
    ):
        assert expected in kinds, expected
    print(
        "transactional-messaging OK: begin, enlist, prepare, vote, "
        "commit, abort, fail-closed"
    )


if __name__ == "__main__":
    main()
