"""AI safety via debate (argue/judge/transcript) interface, simulated.

Research motivation: Irving, Christiano, and Amodei's debate game
(2018) and its successors (double-down / prover-estimator / scalable
oversight literature) reduce AI safety evaluation to one operational
shape: two sides argue a question under a shared transcript, and a
judge decides the winner. The transcript is evidence; the judge's
verdict is data.

This module is the *debate ledger* half of that shape:

- ``Debate.debate(debate_id, topic_digest, seq)`` -- open one debate.
  The question is pinned by ``sha256:`` digest only; raw text never
  enters a record.
- ``Debate.argue(debate_id, side, argument_id, seq, argument_digest="")``
  -- book one argument from a pinned side (``side-a`` / ``side-b``).
  The argument content is digested off-ledger; the record keeps the
  pin, the side, and the ordering.
- ``Debate.judge(debate_id, verdict, seq)`` -- book the judge's verdict
  over the pinned vocabulary (``side-a-wins`` / ``side-b-wins`` /
  ``tie``). The verdict is *data*, never a finding of fact about any
  real model -- exactly once per debate.
- ``Debate.transcript(debate_id, seq)`` -- pure read view of the full
  debate (opener + ordered arguments + verdict) as a frozen
  ``TranscriptReport``; validates the seq shape, consumes nothing,
  writes no audit row.
- ``debate_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``debate-opened`` / ``argued`` / ``judged`` / ``rejected``);
  caller-supplied seqs only. Raw debate content never crosses the
  audit boundary -- audit rows carry ids, sides, digests, verdicts,
  and counts only.

Fail-closed edges (fail loudly, never guess):

- ``debate_id`` / ``argument_id`` must be non-empty str, <= 256 chars,
  no whitespace.
- ``topic_digest`` / ``argument_digest`` must be ``sha256:<64hex>``
  pins (topic pin required; argument pin optional but validated when
  supplied).
- ``side`` must be ``side-a`` or ``side-b``.
- ``argue`` on an unknown debate raises ``UnknownDebateError``;
  duplicate argument ids are refused.
- ``judge`` requires at least one argument booked and runs exactly
  once; verdicts outside the pinned vocabulary are refused.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* debates, *host-reported* arguments, and
  *host-reported* verdicts. A booked ``side-a-wins`` verdict means the
  host reported that side won -- the module ran no debate, judged no
  reasoning quality, and proves nothing about any real model's safety
  or alignment.
- The transcript is a ledger of pins, never the arguments' content;
  reading it back proves ordering and integrity, not soundness.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if debate state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

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
DEBATE_VERSION = "debate.v1"

#: Schema pin carried by records and audit events.
DEBATE_SCHEMA = "northstar.debate.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_DEBATE_OPENED = "debate-opened"
KIND_ARGUED = "argued"
KIND_JUDGED = "judged"
KIND_REJECTED = "rejected"
_KINDS = (KIND_DEBATE_OPENED, KIND_ARGUED, KIND_JUDGED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"topic", "argument", "content", "text", "payload", "raw", "transcript",
     "evidence", "prompt", "response", "value"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned side vocabulary. Sides are bookkeeping labels, not positions.
SIDE_A = "side-a"
SIDE_B = "side-b"
SIDES = (SIDE_A, SIDE_B)

#: Pinned judge-verdict vocabulary. Verdicts are host-reported data.
VERDICT_SIDE_A_WINS = "side-a-wins"
VERDICT_SIDE_B_WINS = "side-b-wins"
VERDICT_TIE = "tie"
VERDICTS = (
    VERDICT_SIDE_A_WINS,
    VERDICT_SIDE_B_WINS,
    VERDICT_TIE,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class DebateError(Exception):
    """Base error for the debate ledger (programming errors)."""


class BadIdError(DebateError):
    """Raised when a debate/argument id is malformed."""


class DuplicateDebateError(DebateError):
    """Raised when a debate id is opened twice."""


class UnknownDebateError(DebateError):
    """Raised when a debate id names no opened debate."""


class BadDigestError(DebateError):
    """Raised when a topic/argument digest is not a sha256: pin."""


class BadSideError(DebateError):
    """Raised when a debate side is not in the pinned vocabulary."""


class DuplicateArgumentError(DebateError):
    """Raised when an argument id is booked twice."""


class BadVerdictError(DebateError):
    """Raised when a judge verdict is not in the pinned vocabulary."""


class AlreadyJudgedError(DebateError):
    """Raised when a debate is judged twice (judgment is terminal)."""


class NoArgumentsError(DebateError):
    """Raised when judge() is called before any argument is booked."""


class SeqOrderError(DebateError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(DebateError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": DEBATE_SCHEMA,
        "parts": list(parts),
    })


def debate_audit_event(kind: str, detail: Dict[str, object],
                       seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the debate ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": DEBATE_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class DebateRecord:
    """Frozen record of one opened debate (topic pinned, never its text)."""
    debate_id: str
    topic_digest: str
    seq: int
    digest: str

    def verify(self, debate_id: str, topic_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("debate", debate_id, topic_digest, self.seq)


@dataclass(frozen=True)
class ArgumentRecord:
    """Frozen record of one booked argument (pin + side + order)."""
    argument_id: str
    debate_id: str
    side: str
    argument_digest: str
    seq: int
    digest: str

    def verify(self, debate_id: str, side: str,
               argument_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "argument", self.argument_id, debate_id, side, argument_digest,
            self.seq)


@dataclass(frozen=True)
class JudgmentRecord:
    """Frozen record of the judge's terminal verdict (verdict as data)."""
    debate_id: str
    verdict: str
    side_a_arguments: int
    side_b_arguments: int
    seq: int
    digest: str

    def verify(self, debate_id: str, verdict: str,
               counts: Tuple[int, int]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        side_a, side_b = counts
        return self.digest == _pin(
            "judgment", debate_id, verdict, side_a, side_b, self.seq)


@dataclass(frozen=True)
class TranscriptEntry:
    """One frozen line of a debate transcript (ids and pins only)."""
    argument_id: str
    side: str
    argument_digest: str
    seq: int


@dataclass(frozen=True)
class TranscriptReport:
    """Pure read view of a full debate: opener, arguments, verdict."""
    debate_id: str
    topic_digest: str
    arguments: Tuple[TranscriptEntry, ...]
    verdict: Optional[str]
    digest: str

    def verify(self, debate_id: str, topic_digest: str,
               argument_ids: Tuple[str, ...],
               verdict: Optional[str]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "transcript", debate_id, topic_digest, list(argument_ids),
            verdict or "")


class Debate:
    """AI-safety debate ledger (declared debates, booked arguments)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._debates: Dict[str, DebateRecord] = {}
        self._arguments: Dict[str, ArgumentRecord] = {}
        self._argument_order: Tuple[str, ...] = ()
        self._judgments: Dict[str, JudgmentRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, debate_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if debate_id:
            detail["debate_id"] = debate_id
        event = debate_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = debate_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def debate(self, debate_id: str, topic_digest: str,
               seq: int) -> DebateRecord:
        """Open one debate. Pins the topic digest, never the topic text.
        Returns the frozen ``DebateRecord``."""
        self._claim(seq)
        try:
            debate_id = _check_id(debate_id, "debate_id")
            topic_digest = _check_digest(topic_digest, "topic_digest")
            with self._lock:
                if debate_id in self._debates:
                    raise DuplicateDebateError(
                        f"debate already opened: {debate_id!r}")
                record = DebateRecord(
                    debate_id=debate_id,
                    topic_digest=topic_digest,
                    seq=seq,
                    digest=_pin("debate", debate_id, topic_digest, seq),
                )
                self._debates[debate_id] = record
        except DebateError:
            self._burn(seq, debate_id if isinstance(debate_id, str) else "")
            raise
        self._emit(KIND_DEBATE_OPENED,
                   {"debate_id": debate_id,
                    "topic_digest": topic_digest}, seq)
        return record

    def argue(self, debate_id: str, side: str, argument_id: str, seq: int,
              argument_digest: str = "") -> ArgumentRecord:
        """Book one argument from a pinned side for an opened debate.
        Returns the frozen ``ArgumentRecord``."""
        self._claim(seq)
        try:
            debate_id = _check_id(debate_id, "debate_id")
            argument_id = _check_id(argument_id, "argument_id")
            if isinstance(side, bool) or not isinstance(side, str):
                raise BadSideError(
                    f"side must be str, got {type(side).__name__}")
            if side not in SIDES:
                raise BadSideError(
                    f"side must be one of {sorted(SIDES)}, got {side!r}")
            argument_digest = _check_digest(
                argument_digest, "argument_digest", allow_empty=True)
            with self._lock:
                if debate_id not in self._debates:
                    raise UnknownDebateError(
                        f"unknown debate: {debate_id!r}")
                if argument_id in self._arguments:
                    raise DuplicateArgumentError(
                        f"argument already booked: {argument_id!r}")
                record = ArgumentRecord(
                    argument_id=argument_id,
                    debate_id=debate_id,
                    side=side,
                    argument_digest=argument_digest,
                    seq=seq,
                    digest=_pin("argument", argument_id, debate_id, side,
                                argument_digest, seq),
                )
                self._arguments[argument_id] = record
                self._argument_order = self._argument_order + (argument_id,)
        except DebateError:
            self._burn(seq, debate_id if isinstance(debate_id, str) else "")
            raise
        self._emit(KIND_ARGUED,
                   {"debate_id": debate_id, "argument_id": argument_id,
                    "side": side, "argument_digest": argument_digest}, seq)
        return record

    def judge(self, debate_id: str, verdict: str,
              seq: int) -> JudgmentRecord:
        """Book the judge's terminal verdict as data (exactly once).
        Returns the frozen ``JudgmentRecord``."""
        self._claim(seq)
        try:
            debate_id = _check_id(debate_id, "debate_id")
            if isinstance(verdict, bool) or not isinstance(verdict, str):
                raise BadVerdictError(
                    f"verdict must be str, got {type(verdict).__name__}")
            if verdict not in VERDICTS:
                raise BadVerdictError(
                    f"verdict must be one of {sorted(VERDICTS)}, "
                    f"got {verdict!r}")
            with self._lock:
                if debate_id not in self._debates:
                    raise UnknownDebateError(
                        f"unknown debate: {debate_id!r}")
                if debate_id in self._judgments:
                    raise AlreadyJudgedError(
                        f"debate already judged: {debate_id!r}")
                args = [self._arguments[aid] for aid in self._argument_order
                        if self._arguments[aid].debate_id == debate_id]
            if not args:
                raise NoArgumentsError(
                    f"no arguments booked for debate {debate_id!r}")
            side_a = sum(1 for a in args if a.side == SIDE_A)
            side_b = sum(1 for a in args if a.side == SIDE_B)
            with self._lock:
                record = JudgmentRecord(
                    debate_id=debate_id,
                    verdict=verdict,
                    side_a_arguments=side_a,
                    side_b_arguments=side_b,
                    seq=seq,
                    digest=_pin("judgment", debate_id, verdict,
                                side_a, side_b, seq),
                )
                self._judgments[debate_id] = record
        except DebateError:
            self._burn(seq, debate_id if isinstance(debate_id, str) else "")
            raise
        self._emit(KIND_JUDGED,
                   {"debate_id": debate_id, "verdict": verdict,
                    "side_a_arguments": side_a,
                    "side_b_arguments": side_b}, seq)
        return record

    def transcript(self, debate_id: str, seq: int) -> TranscriptReport:
        """Pure read view of a full debate (validates seq shape, consumes
        nothing, writes no audit row). Returns the frozen
        ``TranscriptReport``."""
        _check_seq(seq)
        debate_id = _check_id(debate_id, "debate_id")
        with self._lock:
            if debate_id not in self._debates:
                raise UnknownDebateError(
                    f"unknown debate: {debate_id!r}")
            opener = self._debates[debate_id]
            entries = tuple(
                TranscriptEntry(
                    argument_id=aid,
                    side=self._arguments[aid].side,
                    argument_digest=self._arguments[aid].argument_digest,
                    seq=self._arguments[aid].seq,
                )
                for aid in self._argument_order
                if self._arguments[aid].debate_id == debate_id
            )
            judgment = self._judgments.get(debate_id)
            verdict = judgment.verdict if judgment is not None else None
            argument_ids = tuple(e.argument_id for e in entries)
            return TranscriptReport(
                debate_id=debate_id,
                topic_digest=opener.topic_digest,
                arguments=entries,
                verdict=verdict,
                digest=_pin("transcript", debate_id, opener.topic_digest,
                            list(argument_ids), verdict or ""),
            )

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "debates": len(self._debates),
                "arguments": len(self._arguments),
                "judgments": len(self._judgments),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: open, argue, judge, transcript, verify pins, audit."""
    db = Debate()
    topic = "sha256:" + "0" * 64
    rec = db.debate("db-1", topic, 1)
    assert rec.verify("db-1", topic)
    a1 = db.argue("db-1", SIDE_A, "arg-1", 2, "sha256:" + "a" * 64)
    assert a1.verify("db-1", SIDE_A, "sha256:" + "a" * 64)
    a2 = db.argue("db-1", SIDE_B, "arg-2", 3)
    assert a2.verify("db-1", SIDE_B, "")
    judg = db.judge("db-1", VERDICT_SIDE_A_WINS, 4)
    assert judg.verify("db-1", VERDICT_SIDE_A_WINS, (1, 1))
    t = db.transcript("db-1", 4)  # pure read: seq reuse is legal
    assert len(t.arguments) == 2
    assert t.verdict == VERDICT_SIDE_A_WINS
    assert t.verify("db-1", topic, ("arg-1", "arg-2"), VERDICT_SIDE_A_WINS)
    assert db.stats()["arguments"] == 2
    # Refusal spot-checks consume their seqs.
    db.debate("db-empty", "sha256:" + "f" * 64, 5)
    seq = 6
    for thunk in (
        lambda s: db.debate("db-1", topic, s),
        lambda s: db.debate("bad id!", topic, s),
        lambda s: db.debate("db-2", "not-a-pin", s),
        lambda s: db.argue("nope", SIDE_A, "arg-9", s),
        lambda s: db.argue("db-1", "side-c", "arg-9", s),
        lambda s: db.argue("db-1", SIDE_A, "arg-1", s),
        lambda s: db.argue("db-1", SIDE_A, "arg-9", s, "bad-pin"),
        lambda s: db.judge("db-empty", VERDICT_TIE, s),
        lambda s: db.judge("db-1", "side-a-wins!", s),
        lambda s: db.judge("db-1", VERDICT_TIE, s),
        lambda s: db.judge("nope", VERDICT_TIE, s),
    ):
        try:
            thunk(seq)
        except DebateError:
            seq += 1
        else:
            raise AssertionError("refusal expected")
    assert len(db.audit_log()) == len(
        [e for e in db.audit_log() if e["kind"] != KIND_REJECTED]) + 11
    # Seq rewind raises bare without consuming.
    try:
        db.debate("db-3", topic, 1)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("rewind expected")
    print("debate OK: open, argue, judge, transcript, pins, audit")


if __name__ == "__main__":
    main()
