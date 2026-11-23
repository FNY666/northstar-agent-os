"""Changelog: append-only op log for state recovery.

Research motivation: crash recovery (ARIES), state-machine replication,
and event sourcing all rest on one primitive -- an append-only log of
*m mutations* that a crashed or stale replica replays to rebuild state.
A changelog is the recovery half of a durable system: producers append
opaque operations, consumers replay them through a host-supplied applier,
and truncation moves the recovery point forward only after the host has
pinned the state that incorporates the dropped prefix.

This module is the op-log *interface*, distinct from
``write_ahead_log.py`` (KV-mutation specific, chain-linked records,
fold-to-state recovery): here entries are generic ``op``/``key``/``value``
operations, integrity is positional (each entry pins its own position,
so replay detects gaps), and truncation is guarded by a digest over the
prefix actually replayed through the host's applier.

Public API:

- ``Changelog`` -- RLock-guarded append-only log.
  ``append(op, key, value, seq)`` returns a frozen ``ChangelogEntry``
  with the next dense position. ``replay(from_pos=0, applier=None)``
  applies entries in order through the host's ``applier(entry)`` and
  returns a frozen ``ReplayReport``. ``truncate(upto_pos, seq)`` drops
  the retained prefix ``[base_pos, upto_pos)`` (host-attested).
  ``checkpoint(upto_pos, applier, seq)`` replays the prefix through the
  applier, pins the resulting state digest, and truncates atomically --
  the recommended truncation path. ``verify()`` recomputes every digest;
  ``verify_strict()`` raises on the first broken entry.
- ``ChangelogEntry`` -- frozen record: ``pos``, ``op``, ``key``,
  ``value``, ``seq``, ``digest`` (``sha256:`` pin over the canonical
  body, including ``pos``).
- ``ReplayReport`` / ``TruncationRecord`` -- frozen outcome records.
- ``changelog_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``-shaped
  record, fixed kind vocabulary: ``"appended"``, ``"replayed"``,
  ``"truncated"``, ``"checkpointed"``, ``"rejected"``.

Honest scope:

- Positions are dense and never renumbered: after truncation the log
  keeps a ``base_pos`` offset, so a position names the same entry
  forever. A position is a *name*, never a proof the entry was applied.
- ``replay`` proves ordering and content integrity, not that the applier
  did anything correct -- the applier is host code, and its exceptions
  abort the replay wrapped in ``ReplayError``.
- ``truncate`` trusts the host's claim that the dropped prefix is safely
  persisted; the module cannot verify external state. ``checkpoint`` is
  stronger: the ``state_digest`` it pins is recomputed by the module
  from the applier's own results over the dropped prefix, so the digest
  names exactly the history being discarded.
- Digests bind the *reported* operations. A host that appends lies gets
  a perfectly consistent log of lies -- same GIGO boundary as every
  other bookkeeping module in this tree.
- This is an in-memory interface, not a storage engine. Pair with the
  durable audit writer for crash recovery.

Version pin: ``changelog.v1`` / schema pin ``northstar.changelog.v1``.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Module version.
CHANGELOG_VERSION = "changelog.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.changelog.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {"appended", "replayed", "truncated", "checkpointed", "rejected"}
)

#: Digest domain prefix; keeps pins distinct from sibling modules.
_DIGEST_DOMAIN = b"northstar-changelog.v1\x00"

#: Guardrails.
_MAX_OP_LEN = 256
_MAX_KEY_LEN = 1024
_MAX_POS = 2**63 - 1


class ChangelogError(Exception):
    """Base error for changelog failures. Fail-closed, never silent."""


class ReplayError(ChangelogError):
    """Raised when the host applier fails or yields junk during replay."""


class TruncationError(ChangelogError):
    """Raised when a truncation/checkpoint request is out of bounds."""


class VerificationError(ChangelogError):
    """Raised by ``verify_strict`` on the first tampered entry."""

    def __init__(self, pos: int, reason: str) -> None:
        super().__init__(f"entry at pos {pos} failed verification: {reason}")
        self.pos = pos
        self.reason = reason


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_pos(pos: object, name: str = "pos") -> int:
    if isinstance(pos, bool) or not isinstance(pos, int):
        raise TypeError(f"{name} must be int, got {type(pos).__name__}")
    if pos < 0:
        raise ValueError(f"{name} must be non-negative")
    if pos > _MAX_POS:
        raise ValueError(f"{name} exceeds {_MAX_POS}")
    return pos


def _check_op(op: object) -> str:
    if isinstance(op, bool) or not isinstance(op, str):
        raise TypeError(f"op must be str, got {type(op).__name__}")
    if not op:
        raise ValueError("op must be non-empty")
    if len(op) > _MAX_OP_LEN:
        raise ValueError(f"op exceeds {_MAX_OP_LEN} chars")
    return op


def _check_key(key: object) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise TypeError(f"key must be str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must be non-empty")
    if len(key) > _MAX_KEY_LEN:
        raise ValueError(f"key exceeds {_MAX_KEY_LEN} chars")
    return key


def _canonicalize(value: Any) -> str:
    """Canonical string form for digesting. Fail-closed on ambiguity.

    Ints are exact (arbitrary precision); integral floats beyond 2**53
    are refused (same JCS precision caveat as ``secure_aggregation``);
    bools encode distinctly from ints (``true`` vs ``1``); dict keys must
    be str and are sorted.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/inf are not canonicalizable")
        if value.is_integer() and abs(value) > 2**53:
            raise ValueError("integral float beyond 2**53 loses precision")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str")
        items = sorted(value.items(), key=lambda kv: kv[0])
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=True) + ":" + _canonicalize(v)
                for k, v in items
            )
            + "}"
        )
    raise TypeError(f"unsupported value type: {type(value).__name__}")


def _check_value(value: Any) -> Any:
    """Validate that a value is canonicalizable. Returns it unchanged."""
    _canonicalize(value)  # raises fail-closed on junk
    return value


def _digest_entry(pos: int, op: str, key: str, value: Any, seq: int) -> str:
    """``sha256:`` pin over the canonical entry body, including ``pos``."""
    body = (
        _canonicalize(pos)
        + "\x00"
        + json.dumps(op, ensure_ascii=True)
        + "\x00"
        + json.dumps(key, ensure_ascii=True)
        + "\x00"
        + _canonicalize(value)
        + "\x00"
        + _canonicalize(seq)
    )
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


def _digest_results(results: Tuple[Any, ...]) -> str:
    """``sha256:`` pin over the canonical applier-result list."""
    body = "[" + ",".join(_canonicalize(r) for r in results) + "]"
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChangelogEntry:
    """One immutable log record.

    ``digest`` pins ``pos``/``op``/``key``/``value``/``seq`` together, so
    an entry moved to another position (or edited) no longer verifies.
    """

    pos: int
    op: str
    key: str
    value: Any
    seq: int
    digest: str

    def __post_init__(self) -> None:
        _check_pos(self.pos)
        _check_op(self.op)
        _check_key(self.key)
        _check_value(self.value)
        _check_seq(self.seq)
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")
        expected = _digest_entry(self.pos, self.op, self.key, self.value, self.seq)
        if self.digest != expected:
            raise ValueError("digest does not match entry body")

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "pos": self.pos,
            "op": self.op,
            "key": self.key,
            "value": self.value,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ReplayReport:
    """Outcome of one ``replay`` call."""

    start_pos: int
    end_pos: int
    entries_applied: int
    result_digest: str

    def __post_init__(self) -> None:
        _check_pos(self.start_pos, "start_pos")
        _check_pos(self.end_pos, "end_pos")
        if self.end_pos < self.start_pos:
            raise ValueError("end_pos must be >= start_pos")
        if isinstance(self.entries_applied, bool) or not isinstance(
            self.entries_applied, int
        ):
            raise TypeError("entries_applied must be int")
        if self.entries_applied < 0:
            raise ValueError("entries_applied must be non-negative")
        if not isinstance(self.result_digest, str) or not self.result_digest.startswith(
            "sha256:"
        ):
            raise TypeError("result_digest must be a 'sha256:' pin")

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "entries_applied": self.entries_applied,
            "result_digest": self.result_digest,
        }


@dataclass(frozen=True)
class TruncationRecord:
    """Outcome of one ``truncate`` / ``checkpoint`` call.

    ``state_digest`` is ``None`` for host-attested ``truncate`` (the
    module did not see the state); for ``checkpoint`` it is the module-
    recomputed digest of the applier results over the dropped prefix.
    """

    base_pos: int
    upto_pos: int
    dropped: int
    state_digest: Optional[str]
    seq: int

    def __post_init__(self) -> None:
        _check_pos(self.base_pos, "base_pos")
        _check_pos(self.upto_pos, "upto_pos")
        if self.upto_pos < self.base_pos:
            raise ValueError("upto_pos must be >= base_pos")
        if isinstance(self.dropped, bool) or not isinstance(self.dropped, int):
            raise TypeError("dropped must be int")
        if self.dropped < 0 or self.dropped != self.upto_pos - self.base_pos:
            raise ValueError("dropped must equal upto_pos - base_pos")
        if self.state_digest is not None and (
            not isinstance(self.state_digest, str)
            or not self.state_digest.startswith("sha256:")
        ):
            raise TypeError("state_digest must be a 'sha256:' pin or None")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "base_pos": self.base_pos,
            "upto_pos": self.upto_pos,
            "dropped": self.dropped,
            "state_digest": self.state_digest,
            "seq": self.seq,
        }


class Changelog:
    """Append-only op log with positional integrity and guarded truncation.

    Positions are dense and stable: ``append`` mints ``base_pos + len``,
    and truncation only advances ``base_pos`` -- a position always names
    the same entry. All caller-supplied seqs (no wall-clock); RLock-
    guarded; stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: List[ChangelogEntry] = []
        self._base_pos = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def base_pos(self) -> int:
        """Oldest retained position (0 until the first truncation)."""
        with self._lock:
            return self._base_pos

    def head(self) -> int:
        """Next position to be minted (one past the newest entry)."""
        with self._lock:
            return self._base_pos + len(self._entries)

    def is_empty(self) -> bool:
        """True when no entries are retained."""
        return len(self) == 0

    def append(self, op: str, key: str, value: Any, seq: int) -> ChangelogEntry:
        """Append one operation. Returns the frozen entry.

        Fail-closed: bad op/key/value/seq raise and nothing is appended.
        """
        op = _check_op(op)
        key = _check_key(key)
        value = _check_value(value)
        seq = _check_seq(seq)
        with self._lock:
            pos = self._base_pos + len(self._entries)
            entry = ChangelogEntry(
                pos=pos,
                op=op,
                key=key,
                value=value,
                seq=seq,
                digest=_digest_entry(pos, op, key, value, seq),
            )
            self._entries.append(entry)
            return entry

    def entry(self, pos: int) -> ChangelogEntry:
        """Fetch one retained entry. ``ChangelogError`` when out of range."""
        pos = _check_pos(pos)
        with self._lock:
            idx = pos - self._base_pos
            if idx < 0 or idx >= len(self._entries):
                raise ChangelogError(
                    f"pos {pos} not retained (base_pos={self._base_pos}, "
                    f"head={self._base_pos + len(self._entries)})"
                )
            return self._entries[idx]

    def entries_since(self, pos: int) -> Tuple[ChangelogEntry, ...]:
        """All retained entries from ``pos`` (inclusive) to head."""
        pos = _check_pos(pos)
        with self._lock:
            head = self._base_pos + len(self._entries)
            if pos < self._base_pos or pos > head:
                raise ChangelogError(
                    f"pos {pos} out of retained range "
                    f"[{self._base_pos}, {head}]"
                )
            return tuple(self._entries[pos - self._base_pos :])

    def verify(self) -> bool:
        """Recompute every retained digest. ``True`` iff all verify."""
        with self._lock:
            entries = list(self._entries)
        for entry in entries:
            if entry.digest != _digest_entry(
                entry.pos, entry.op, entry.key, entry.value, entry.seq
            ):
                return False
        return True

    def verify_strict(self) -> None:
        """Like ``verify`` but raises ``VerificationError`` on first failure."""
        with self._lock:
            entries = list(self._entries)
        for entry in entries:
            expected = _digest_entry(
                entry.pos, entry.op, entry.key, entry.value, entry.seq
            )
            if entry.digest != expected:
                raise VerificationError(entry.pos, "digest mismatch")

    def replay(
        self,
        from_pos: int = 0,
        applier: Optional[Callable[[ChangelogEntry], Any]] = None,
    ) -> ReplayReport:
        """Replay entries ``[from_pos, head)`` in order.

        When ``applier`` is given, each entry is passed through it and
        the results are pinned into ``result_digest``. An applier
        exception aborts the replay wrapped in ``ReplayError`` (the
        applier's own state at that point is unknown to this module).
        Applier results must be canonicalizable, else ``ReplayError``.
        """
        from_pos = _check_pos(from_pos, "from_pos")
        if applier is not None and not callable(applier):
            raise TypeError(
                f"applier must be callable, got {type(applier).__name__}"
            )
        with self._lock:
            head = self._base_pos + len(self._entries)
            if from_pos < self._base_pos or from_pos > head:
                raise ChangelogError(
                    f"from_pos {from_pos} out of retained range "
                    f"[{self._base_pos}, {head}]"
                )
            entries = list(self._entries[from_pos - self._base_pos :])
        results: List[Any] = []
        if applier is not None:
            for entry in entries:
                try:
                    result = applier(entry)
                except Exception as exc:
                    raise ReplayError(
                        f"applier failed at pos {entry.pos}"
                    ) from exc
                try:
                    _canonicalize(result)
                except (TypeError, ValueError) as exc:
                    raise ReplayError(
                        f"applier result at pos {entry.pos} not canonicalizable"
                    ) from exc
                results.append(result)
        return ReplayReport(
            start_pos=from_pos,
            end_pos=head,
            entries_applied=len(entries),
            result_digest=_digest_results(tuple(results)),
        )

    def truncate(self, upto_pos: int, seq: int) -> TruncationRecord:
        """Drop retained entries ``[base_pos, upto_pos)``. Host-attested.

        The module cannot verify the host's external state; use
        ``checkpoint`` when the digest over the dropped prefix matters.
        ``TruncationError`` when ``upto_pos`` is outside
        ``[base_pos, head]``.
        """
        upto_pos = _check_pos(upto_pos, "upto_pos")
        seq = _check_seq(seq)
        with self._lock:
            head = self._base_pos + len(self._entries)
            if upto_pos < self._base_pos or upto_pos > head:
                raise TruncationError(
                    f"upto_pos {upto_pos} out of range [{self._base_pos}, {head}]"
                )
            dropped = upto_pos - self._base_pos
            del self._entries[:dropped]
            old_base = self._base_pos
            self._base_pos = upto_pos
        return TruncationRecord(
            base_pos=old_base,
            upto_pos=upto_pos,
            dropped=dropped,
            state_digest=None,
            seq=seq,
        )

    def checkpoint(
        self,
        upto_pos: int,
        applier: Callable[[ChangelogEntry], Any],
        seq: int,
    ) -> TruncationRecord:
        """Replay ``[base_pos, upto_pos)`` through ``applier``, then truncate.

        The returned record pins ``state_digest`` recomputed by this
        module from the applier's own results over the dropped prefix, so
        the digest names exactly the history being discarded. Atomic with
        respect to other ``Changelog`` calls (RLock).
        """
        upto_pos = _check_pos(upto_pos, "upto_pos")
        seq = _check_seq(seq)
        if not callable(applier):
            raise TypeError(
                f"applier must be callable, got {type(applier).__name__}"
            )
        with self._lock:
            head = self._base_pos + len(self._entries)
            if upto_pos < self._base_pos or upto_pos > head:
                raise TruncationError(
                    f"upto_pos {upto_pos} out of range [{self._base_pos}, {head}]"
                )
            prefix = list(self._entries[: upto_pos - self._base_pos])
        results: List[Any] = []
        for entry in prefix:
            try:
                result = applier(entry)
            except Exception as exc:
                raise ReplayError(
                    f"checkpoint applier failed at pos {entry.pos}"
                ) from exc
            try:
                _canonicalize(result)
            except (TypeError, ValueError) as exc:
                raise ReplayError(
                    f"checkpoint applier result at pos {entry.pos} "
                    "not canonicalizable"
                ) from exc
            results.append(result)
        state_digest = _digest_results(tuple(results))
        with self._lock:
            # Re-check bounds: another thread may have truncated meanwhile.
            head = self._base_pos + len(self._entries)
            if upto_pos < self._base_pos or upto_pos > head:
                raise TruncationError(
                    f"upto_pos {upto_pos} out of range [{self._base_pos}, {head}]"
                )
            old_base = self._base_pos
            dropped = upto_pos - old_base
            del self._entries[:dropped]
            self._base_pos = upto_pos
        return TruncationRecord(
            base_pos=old_base,
            upto_pos=upto_pos,
            dropped=dropped,
            state_digest=state_digest,
            seq=seq,
        )

    def as_dict(self) -> dict:
        """JSON-safe snapshot with the schema pin."""
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "base_pos": self._base_pos,
                "head": self._base_pos + len(self._entries),
                "retained": len(self._entries),
            }


def changelog_audit_event(
    kind: str,
    seq: int,
    pos: Optional[int] = None,
    count: Optional[int] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a changelog operation.

    ``kind`` is one of ``"appended"`` / ``"replayed"`` / ``"truncated"`` /
    ``"checkpointed"`` / ``"rejected"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    record: Dict[str, Any] = {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "seq": _check_seq(seq),
    }
    if pos is not None:
        record["pos"] = _check_pos(pos)
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError(f"count must be int, got {type(count).__name__}")
        if count < 0:
            raise ValueError("count must be non-negative")
        record["count"] = count
    return record


def main() -> None:
    """Self-check: append, replay, truncate, checkpoint, verify."""
    log = Changelog()
    assert log.is_empty()
    assert log.base_pos() == 0
    assert log.head() == 0

    e0 = log.append("put", "k1", {"v": 1}, 1)
    e1 = log.append("put", "k2", [1, 2], 2)
    e2 = log.append("delete", "k1", None, 3)
    assert (e0.pos, e1.pos, e2.pos) == (0, 1, 2)
    assert log.head() == 3
    assert len(log) == 3
    assert log.verify()

    # Replay through a host applier; positions stay dense and ordered.
    seen: List[int] = []
    report = log.replay(0, lambda e: seen.append(e.pos) or e.op)
    assert seen == [0, 1, 2]
    assert report.entries_applied == 3
    assert report.start_pos == 0 and report.end_pos == 3

    # entries_since with a bad position is a policy refusal, not a guess.
    try:
        log.entries_since(99)
        raise AssertionError("entries_since(99) must raise")
    except ChangelogError:
        pass

    # Checkpoint folds the prefix and moves the recovery point.
    rec = log.checkpoint(2, lambda e: (e.op, e.key), 4)
    assert rec.dropped == 2
    assert rec.state_digest is not None and rec.state_digest.startswith("sha256:")
    assert log.base_pos() == 2
    assert len(log) == 1
    assert log.entry(2).op == "delete"
    assert log.verify()

    # A checkpoint digest is recomputable from the applier results.
    again = Changelog()
    again.append("put", "k1", {"v": 1}, 1)
    again.append("put", "k2", [1, 2], 2)
    rec2 = again.checkpoint(2, lambda e: (e.op, e.key), 5)
    assert rec2.state_digest == rec.state_digest

    # Plain truncate is host-attested: no digest, just bookkeeping.
    rec3 = log.truncate(3, 6)
    assert rec3.state_digest is None
    assert log.is_empty()
    assert log.head() == 3

    print("changelog OK: append, replay, truncate, checkpoint, verify")
    print("audit:", changelog_audit_event("checkpointed", 7, pos=2, count=2)["kind"])


if __name__ == "__main__":
    main()
