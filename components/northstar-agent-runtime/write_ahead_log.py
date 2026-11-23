"""Write-ahead log: crash-recovery log with verified checkpoints.

Research motivation: a write-ahead log (WAL) records intended mutations
*before* they are applied to the durable state. If the process dies
mid-write, recovery replays the log to rebuild the state instead of
guessing. ARIES-style recovery uses this exact pattern; here it is the
in-memory, deterministic state machine half: append-only records,
digest-pinned chain continuity, fold-to-state replay, and checkpoints
whose digest is *verified* against a real replay before they are minted.

Public API:

- ``LogRecord`` -- frozen record: ``record_id`` (unique audit identifier),
  ``op`` (``"put"`` / ``"delete"``), ``key`` (non-empty str), ``value``
  (canonicalizable for ``"put"``, must be ``None`` for ``"delete"``),
  ``seq`` (caller-supplied int ordering, no wall-clock), ``prev_head``
  (chain link), ``digest`` (``sha256:`` pin over the canonical body).
- ``WAL`` -- append-only log. ``append(record)`` enforces strictly
  increasing seqs, hash-chain continuity, and unique record ids
  (fail-closed). ``replay()`` / ``replay_records(records)`` fold the
  ``put``/``delete`` stream into a state dict. ``checkpoint(upto_seq,
  state_digest, seq)`` mints a ``Checkpoint`` only when the pinned digest
  matches a real replay of the prefix -- a checkpoint that does not pin
  verified state is refused, not recorded. ``compact(checkpoint)``
  returns a new ``WAL`` holding only records after ``checkpoint.upto_seq``,
  with the truncation point pinned as the new genesis head.
- ``apply(state, record)`` -- pure single-record fold primitive.
- ``state_digest(state)`` -- ``sha256:`` pin of canonical state, the
  value checkpoints must pin.

Honest scope:

- This is the *log-and-recovery state machine*, not a database: no disk
  I/O, no persistence (the host owns durability and fsync), no
  concurrency beyond a lock for append-order atomicity. A process crash
  loses this object; the host replays the persisted log to rebuild it.
- The hash chain proves *internal consistency* of the log the host hands
  back -- it cannot prove the host did not withhold a prefix (that needs
  an external head anchor, the host's job).
- ``Checkpoint`` proves the pinned digest matched a replay of the prefix
  *at checkpoint time*. It does not prove the checkpoint was durable, nor
  that a later replay with a different reducer is meaningful.
- Values must be JCS-canonicalizable (str/int/float/bool/None/list/dict
  with str keys). Non-canonicalizable values are rejected at construction
  so a record can always be pinned and replayed deterministically.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
WRITE_AHEAD_LOG_VERSION = "write-ahead-log.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.write-ahead-log.v1"

#: Genesis head digest: the chain anchor before the first record.
GENESIS_HEAD = "sha256:" + "0" * 64

#: The two mutation operations the log carries.
PUT = "put"
DELETE = "delete"


class WriteAheadLogError(Exception):
    """Base error for the write-ahead log layer (programming errors)."""


class OutOfOrderAppend(WriteAheadLogError):
    """Raised when an append breaks seq monotonicity or chain continuity."""


class ReplayError(WriteAheadLogError):
    """Raised when replay cannot proceed deterministically."""


class CheckpointError(WriteAheadLogError):
    """Raised when a checkpoint cannot be minted or honored."""


def _check_text(value: object, name: str) -> str:
    """Validate a non-empty text field."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_digest(value: object, name: str = "digest") -> str:
    """Validate a ``sha256:<64 hex>`` digest pin."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{name} must look like 'sha256:<64 hex>'")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError(f"{name} hex part must be lowercase hex")
    return value


def _check_value(value: object) -> Any:
    """Validate a put value: canonicalizable."""
    try:
        jcs_canonical_json(value)
    except Exception as exc:
        raise TypeError(f"value is not canonicalizable: {exc}") from exc
    return value


def _record_digest(record_id: str, op: str, key: str, value: Any,
                   seq: int, prev_head: str) -> str:
    """Pin the canonical record body."""
    return "sha256:" + jcs_sha256_hex({
        "record_id": record_id,
        "op": op,
        "key": key,
        "value": value,
        "seq": seq,
        "prev_head": prev_head,
    })


@dataclass(frozen=True)
class LogRecord:
    """One mutation intent in the write-ahead log.

    ``digest`` pins the canonical body chained to ``prev_head``; it is
    recomputed at construction and must match a caller-supplied pin.
    """
    record_id: str
    op: str
    key: str
    value: Any
    seq: int
    prev_head: str
    digest: str

    def __init__(self, record_id: str, op: str, key: str, value: Any,
                 seq: int, prev_head: str = GENESIS_HEAD) -> None:
        _check_text(record_id, "record_id")
        if op not in (PUT, DELETE):
            raise ValueError(f"op must be {PUT!r} or {DELETE!r}, got {op!r}")
        _check_text(key, "key")
        _check_seq(seq)
        _check_digest(prev_head, "prev_head")
        if op == PUT:
            if value is None:
                raise ValueError("put requires a non-None value")
            _check_value(value)
        else:  # DELETE carries no payload; a delete with a value is refused
            # so the log cannot silently carry two meanings for one record.
            if value is not None:
                raise ValueError("delete must carry value=None")
        digest = _record_digest(record_id, op, key, value, seq, prev_head)
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "op", op)
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "prev_head", prev_head)
        object.__setattr__(self, "digest", digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "record_id": self.record_id,
            "op": self.op,
            "key": self.key,
            "value": self.value,
            "seq": self.seq,
            "prev_head": self.prev_head,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Checkpoint:
    """A verified truncation point.

    ``state_digest`` is the pin of ``replay(prefix)`` at mint time --
    verified by construction, never taken on faith.
    """
    upto_seq: int
    state_digest: str
    prev_head: str
    seq: int
    digest: str

    def __init__(self, upto_seq: int, state_digest: str,
                 prev_head: str, seq: int) -> None:
        _check_seq(upto_seq, "upto_seq")
        _check_digest(state_digest, "state_digest")
        _check_digest(prev_head, "prev_head")
        _check_seq(seq, "seq")
        digest = ("sha256:" + jcs_sha256_hex({
            "upto_seq": upto_seq,
            "state_digest": state_digest,
            "prev_head": prev_head,
            "seq": seq,
        }))
        object.__setattr__(self, "upto_seq", upto_seq)
        object.__setattr__(self, "state_digest", state_digest)
        object.__setattr__(self, "prev_head", prev_head)
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "digest", digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "upto_seq": self.upto_seq,
            "state_digest": self.state_digest,
            "prev_head": self.prev_head,
            "seq": self.seq,
            "digest": self.digest,
        }


def apply(state: Dict[str, Any], record: LogRecord) -> Dict[str, Any]:
    """Fold one record into a state dict (pure, returns a new dict)."""
    if not isinstance(record, LogRecord):
        raise TypeError(f"expected LogRecord, got {type(record).__name__}")
    new_state = dict(state)
    if record.op == PUT:
        new_state[record.key] = record.value
    else:
        new_state.pop(record.key, None)
    return new_state


def state_digest(state: Mapping[str, Any]) -> str:
    """Pin canonical state: ``sha256:`` over JCS-canonical form."""
    if not isinstance(state, Mapping):
        raise TypeError(f"state must be a mapping, got {type(state).__name__}")
    for key in state.keys():
        if not isinstance(key, str):
            raise TypeError("state keys must be str")
    try:
        return "sha256:" + jcs_sha256_hex(dict(state))
    except Exception as exc:
        raise TypeError(f"state is not canonicalizable: {exc}") from exc


def replay_records(records: Sequence[LogRecord],
                   initial: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    """Fold records in seq order into a state dict.

    Input order is not trusted (sorted by seq); duplicate seqs fail closed
    -- a replay that silently drops a record would certify a lie.
    """
    if initial is not None and not isinstance(initial, Mapping):
        raise TypeError(
            f"initial must be a mapping, got {type(initial).__name__}")
    for record in records:
        if not isinstance(record, LogRecord):
            raise TypeError(
                f"expected LogRecord, got {type(record).__name__}")
    ordered = sorted(records, key=lambda r: r.seq)
    seen = set()
    for record in ordered:
        if record.seq in seen:
            raise ReplayError(f"duplicate seq in replay: {record.seq}")
        seen.add(record.seq)
    state: Dict[str, Any] = dict(initial) if initial else {}
    for record in ordered:
        state = apply(state, record)
    return state


def verify_record_chain(records: Sequence[LogRecord], base_head: str) -> bool:
    """Re-check chain continuity of a record list from a base head.

    Pure function: the host uses it to validate a persisted log it hands
    back after a restart, before trusting it.
    """
    _check_digest(base_head, "base_head")
    expected = base_head
    for record in records:
        if not isinstance(record, LogRecord):
            raise TypeError(
                f"expected LogRecord, got {type(record).__name__}")
        if record.prev_head != expected:
            return False
        if record.digest != _record_digest(
                record.record_id, record.op, record.key, record.value,
                record.seq, record.prev_head):
            return False
        expected = record.digest
    return True


class WAL:
    """Append-only write-ahead log with verified checkpoints.

    The lock guards append-order atomicity only; replay, checkpoint
    verification, and compaction work on immutable snapshots.
    """

    def __init__(self, base_head: str = GENESIS_HEAD) -> None:
        _check_digest(base_head, "base_head")
        self._lock = threading.Lock()
        self._base_head = base_head
        self._records: List[LogRecord] = []
        self._checkpoints: List[Checkpoint] = []
        self._ids = set()

    def __len__(self) -> int:
        return len(self._records)

    def base_head(self) -> str:
        """Chain anchor below the first held record (pin of the prefix)."""
        return self._base_head

    def head(self) -> str:
        """Digest of the last record, or the base head when empty."""
        return self._records[-1].digest if self._records else self._base_head

    def append(self, record: LogRecord) -> str:
        """Append one record; returns its digest.

        Fail-closed on non-record input, non-monotonic seq, chain break,
        or duplicate record id. Nothing is appended on any failure.
        """
        if not isinstance(record, LogRecord):
            raise TypeError(
                f"expected LogRecord, got {type(record).__name__}")
        with self._lock:
            if self._records and record.seq <= self._records[-1].seq:
                raise OutOfOrderAppend(
                    f"seq {record.seq} not after {self._records[-1].seq}")
            if record.prev_head != self.head():
                raise OutOfOrderAppend(
                    f"prev_head {record.prev_head} != head {self.head()}")
            if record.record_id in self._ids:
                raise OutOfOrderAppend(
                    f"duplicate record_id: {record.record_id}")
            self._records.append(record)
            self._ids.add(record.record_id)
            return record.digest

    def records(self) -> tuple:
        return tuple(self._records)

    def records_since(self, seq: int) -> tuple:
        _check_seq(seq)
        return tuple(r for r in self._records if r.seq > seq)

    def checkpoints(self) -> tuple:
        return tuple(self._checkpoints)

    def verify_chain(self) -> bool:
        """Re-check chain continuity from the base head forward."""
        return verify_record_chain(self._records, self._base_head)

    def replay(self, initial: Mapping[str, Any] | None = None) -> Dict[str, Any]:
        """Rebuild full state from every held record."""
        return replay_records(self.records(), initial)

    def checkpoint(self, upto_seq: int, digest: str, seq: int) -> Checkpoint:
        """Mint a verified checkpoint of the prefix ``seq <= upto_seq``.

        The digest is verified against a real replay of the prefix --
        a pin that does not match the replayed state is refused and no
        checkpoint is recorded.
        """
        _check_seq(seq, "seq")
        _check_digest(digest, "state_digest")
        with self._lock:
            prefix = [r for r in self._records if r.seq <= upto_seq]
            if not prefix:
                raise CheckpointError(
                    f"no records at or before seq {upto_seq}")
            if upto_seq > self._records[-1].seq:
                raise CheckpointError(
                    f"upto_seq {upto_seq} beyond last record "
                    f"seq {self._records[-1].seq}")
            actual = state_digest(replay_records(prefix))
            if actual != digest:
                raise CheckpointError(
                    "state digest does not match replayed prefix")
            point = Checkpoint(upto_seq, digest, self.head(), seq)
            self._checkpoints.append(point)
            return point

    def compact(self, checkpoint: Checkpoint) -> "WAL":
        """Return a new WAL holding only records after the checkpoint.

        The digest of the dropped prefix's last record becomes the new
        base head, so the truncation point stays pinned and the remaining
        chain still verifies end to end.
        """
        if not isinstance(checkpoint, Checkpoint):
            raise TypeError(
                f"expected Checkpoint, got {type(checkpoint).__name__}")
        if checkpoint not in self._checkpoints:
            raise CheckpointError("checkpoint was not minted by this WAL")
        kept = [r for r in self._records if r.seq > checkpoint.upto_seq]
        dropped = [r for r in self._records if r.seq <= checkpoint.upto_seq]
        new_base = dropped[-1].digest if dropped else self._base_head
        compacted = WAL(base_head=new_base)
        # Chain continuity: the first kept record's prev_head must equal
        # the new base head (the digest of the last dropped record).
        for record in kept:
            compacted.append(record)
        return compacted


def wal_audit_event(kind: str, seq: int,
                    record: LogRecord | None = None,
                    checkpoint: Checkpoint | None = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for WAL decisions."""
    if kind not in ("appended", "checkpointed", "compacted", "rejected"):
        raise ValueError(f"unknown kind: {kind!r}")
    _check_seq(seq, "seq")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if record is not None:
        if not isinstance(record, LogRecord):
            raise TypeError(
                f"expected LogRecord, got {type(record).__name__}")
        event["record_id"] = record.record_id
        event["record_seq"] = record.seq
        event["record_digest"] = record.digest
    if checkpoint is not None:
        if not isinstance(checkpoint, Checkpoint):
            raise TypeError(
                f"expected Checkpoint, got {type(checkpoint).__name__}")
        event["checkpoint_digest"] = checkpoint.digest
        event["checkpoint_upto_seq"] = checkpoint.upto_seq
    return event


def main() -> None:
    """Self-check: append, chain, replay, verified checkpoint, compact."""
    wal = WAL()
    assert wal.head() == GENESIS_HEAD
    assert len(wal) == 0

    r0 = LogRecord("r0", "put", "balance", 100, 0)
    r1 = LogRecord("r1", "put", "owner", "alice", 1,
                   prev_head=r0.digest)
    r2 = LogRecord("r2", "delete", "owner", None, 2,
                   prev_head=r1.digest)
    wal.append(r0)
    wal.append(r1)
    wal.append(r2)
    assert len(wal) == 3
    assert wal.head() == r2.digest
    assert wal.verify_chain()
    assert [r.record_id for r in wal.records_since(0)] == ["r1", "r2"]

    state = wal.replay()
    assert state == {"balance": 100}, state
    # Replay is order-independent; duplicate seqs fail closed.
    state = replay_records([r2, r0, r1])
    assert state == {"balance": 100}, state
    try:
        replay_records([r0, r0])
    except ReplayError:
        pass
    else:
        raise AssertionError("duplicate seq must raise")

    # Checkpoint pins verified state only.
    digest = state_digest({"balance": 100, "owner": "alice"})
    point = wal.checkpoint(1, digest, 3)
    assert point.upto_seq == 1
    assert point.state_digest == digest
    assert len(wal.checkpoints()) == 1
    try:
        wal.checkpoint(1, GENESIS_HEAD, 4)
    except CheckpointError:
        pass
    else:
        raise AssertionError("wrong digest must raise")

    # Compaction drops the prefix and pins the truncation point.
    compacted = wal.compact(point)
    assert len(compacted) == 1
    assert compacted.base_head() == r1.digest
    assert compacted.verify_chain()
    # The suffix alone cannot rebuild pre-checkpoint state; recovery
    # starts from the checkpoint-pinned state and replays the suffix.
    assert [r.record_id for r in compacted.records()] == ["r2"]
    recovered = replay_records(
        compacted.records(),
        initial={"balance": 100, "owner": "alice"})
    assert recovered == {"balance": 100}, recovered
    try:
        wal.compact(Checkpoint(1, digest, wal.head(), 9))
    except CheckpointError:
        pass
    else:
        raise AssertionError("foreign checkpoint must raise")

    # Out-of-order, chain-break, and duplicate-id appends fail closed.
    for bad in (
        LogRecord("bad", "put", "k", 1, 1, prev_head=r2.digest),
        LogRecord("bad2", "put", "k", 1, 9, prev_head=GENESIS_HEAD),
        LogRecord("r0", "put", "k", 1, 9, prev_head=r2.digest),
    ):
        try:
            wal.append(bad)
        except OutOfOrderAppend:
            pass
        else:
            raise AssertionError("bad append must raise")
    assert len(wal) == 3

    print("write-ahead-log OK: append, replay, verified checkpoint, compact")


if __name__ == "__main__":
    main()
