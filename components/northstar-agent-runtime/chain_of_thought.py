"""Chain-of-thought reasoning (reason/trace) interface, simulated.

Research motivation: chain-of-thought is the standard way to make an
agent's reasoning inspectable -- a declared question, a sequence of
reasoning steps, and a concluded answer, each step linked to the one
before it so the whole chain can be audited later. Without the ledger,
"the agent thought X before doing Y" is an unfalsifiable claim.

This module is the *reasoning ledger* half of that shape. It does not
run a model and cannot judge reasoning quality; it books declared
reasoning decisions and verifies their tamper-evident linkage:

- ``ChainOfThought.begin(chain_id, question_digest, seq)`` -- open a
  reasoning chain for a host-declared question. The question is pinned
  by its ``sha256:`` digest only -- raw question text never enters a
  record or crosses the audit boundary. Returns a frozen ``ChainRecord``.
  Duplicate ids are refused fail-closed; ids are never recycled.
- ``ChainOfThought.reason(chain_id, rationale_digest, confidence, seq)``
  -- book one reasoning step. Returns a frozen ``StepRecord`` whose
  digest hash-links to the previous step (or to the chain record for
  step 1). The rationale is pinned by digest only -- raw reasoning text
  never enters a record. ``confidence`` is host-reported data in
  [0, 1], never a truth claim.
- ``ChainOfThought.conclude(chain_id, answer_digest, seq)`` -- terminal
  step: book the declared answer digest for the chain. Returns a frozen
  ``ConclusionRecord``. A chain can be concluded exactly once.
- ``ChainOfThought.trace(chain_id, seq)`` -- pure read view of the
  chain's step sequence (hashes and seqs, no rationale text).
- ``ChainOfThought.verify(chain_id, seq)`` -- re-walk the hash chain
  and report integrity as data (``ok`` bool); tampering is reported,
  never raised.
- ``chain_of_thought_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``chain-begun`` / ``step-reasoned`` / ``concluded`` /
  ``rejected``); caller-supplied seqs only. Rationale/question/answer
  text banned from the audit boundary -- audit rows carry ids,
  digests, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``chain_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``question_digest`` / ``rationale_digest`` / ``answer_digest`` must
  be ``sha256:``-prefixed 71-char pins.
- ``confidence`` must be a finite float in [0, 1] (ints 0/1 accepted
  and stored as float; bool, NaN, inf, out-of-range refused).
- ``reason`` on an unknown chain raises ``UnknownChainError``; on a
  concluded chain raises ``ConcludedChainError``.
- ``conclude`` on a chain with zero steps raises ``EmptyChainError``;
  a second conclusion raises ``ConcludedChainError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* reasoning: a booked step means the host
  declared this rationale digest at this position with this confidence,
  never that the reasoning is sound, true, or actually ran anywhere.
  Rationale digests are GIGO -- the module cannot inspect, verify, or
  reproduce any real chain of thought.
- ``verify()`` checks the ledger's hash linkage, i.e. that nobody
  edited the booked rows after the fact. It says nothing about the
  quality, honesty, or origin of the reasoning content itself.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if chains must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj):  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
CHAIN_OF_THOUGHT_VERSION = "chain-of-thought.v1"

#: Schema pin carried by records and audit events.
CHAIN_OF_THOUGHT_SCHEMA = "northstar.chain-of-thought.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_CHAIN_BEGUN = "chain-begun"
KIND_STEP_REASONED = "step-reasoned"
KIND_CONCLUDED = "concluded"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CHAIN_BEGUN, KIND_STEP_REASONED, KIND_CONCLUDED,
          KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"question", "rationale", "answer", "text", "content", "value",
     "confidence", "payload", "raw", "prompt", "thought"})

#: Max chain-id length.
_MAX_CHAIN_ID_LEN = 256

#: Expected length of a "sha256:<64 hex>" pin.
_PIN_LEN = len("sha256:") + 64


class ChainOfThoughtError(Exception):
    """Base error for the chain-of-thought ledger (programming errors)."""


class BadChainError(ChainOfThoughtError):
    """Raised when a chain id is malformed."""


class DuplicateChainError(ChainOfThoughtError):
    """Raised when a chain id is opened twice."""


class UnknownChainError(ChainOfThoughtError):
    """Raised when a chain id names no opened chain."""


class ConcludedChainError(ChainOfThoughtError):
    """Raised when reasoning on a concluded chain, or re-concluding."""


class EmptyChainError(ChainOfThoughtError):
    """Raised when concluding a chain with zero steps."""


class BadDigestError(ChainOfThoughtError):
    """Raised when a digest pin is malformed."""


class BadConfidenceError(ChainOfThoughtError):
    """Raised when a confidence value is malformed."""


class SeqOrderError(ChainOfThoughtError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(ChainOfThoughtError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_chain_id(chain_id: object) -> str:
    """Validate a chain id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, str):
        raise BadChainError(f"chain_id must be str, got {type(chain_id).__name__}")
    if not chain_id:
        raise BadChainError("chain_id must not be empty")
    if len(chain_id) > _MAX_CHAIN_ID_LEN:
        raise BadChainError(f"chain_id too long (>{_MAX_CHAIN_ID_LEN} chars)")
    if any(ch.isspace() for ch in chain_id):
        raise BadChainError("chain_id must not contain whitespace")
    return chain_id


def _check_digest(pin: object, name: str) -> str:
    """Validate a sha256: digest pin (71 chars, hex body)."""
    if isinstance(pin, bool) or not isinstance(pin, str):
        raise BadDigestError(f"{name} must be str, got {type(pin).__name__}")
    if len(pin) != _PIN_LEN or not pin.startswith("sha256:"):
        raise BadDigestError(f"{name} must be a sha256: pin, got {pin!r}")
    body = pin[len("sha256:"):]
    if not all(c in "0123456789abcdef" for c in body):
        raise BadDigestError(f"{name} has a non-hex digest body: {pin!r}")
    return pin


def _check_confidence(value: object) -> float:
    """Validate a host-reported confidence: finite float in [0, 1]."""
    if isinstance(value, bool):
        raise BadConfidenceError("confidence must not be bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadConfidenceError(
            f"confidence must be float, got {type(value).__name__}")
    if not math.isfinite(value):
        raise BadConfidenceError(f"confidence must be finite, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadConfidenceError(
            f"confidence must be in [0, 1], got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": CHAIN_OF_THOUGHT_SCHEMA,
        "parts": list(parts),
    })


def _safe_confidence(confidence: float) -> object:
    """Make a confidence JSON-encodable for digest input."""
    if math.isnan(confidence) or math.isinf(confidence):
        return repr(confidence)
    return confidence


def chain_of_thought_audit_event(kind: str, detail: Dict[str, object],
                                 seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the reasoning ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": CHAIN_OF_THOUGHT_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ChainRecord:
    """Frozen record of an opened reasoning chain."""
    chain_id: str
    question_digest: str
    seq: int
    digest: str

    def verify(self, chain_id: str, question_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("chain", chain_id, question_digest,
                                   self.seq)


@dataclass(frozen=True)
class StepRecord:
    """Frozen record of one booked reasoning step (hash-linked)."""
    chain_id: str
    step_no: int  # 1-based position inside the chain.
    rationale_digest: str
    confidence: float
    prev_digest: str  # previous step's digest; chain digest for step 1.
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "step", self.chain_id, self.step_no, self.rationale_digest,
            repr(_safe_confidence(self.confidence)), self.prev_digest,
            self.seq)


@dataclass(frozen=True)
class ConclusionRecord:
    """Frozen terminal record: the chain's declared answer."""
    chain_id: str
    answer_digest: str
    steps: int  # number of reasoning steps at conclusion time.
    head_digest: str  # digest of the last step.
    seq: int
    digest: str

    def verify(self, chain_id: str, answer_digest: str, steps: int,
               head_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "conclude", chain_id, answer_digest, steps, head_digest,
            self.seq)


@dataclass(frozen=True)
class TraceReport:
    """Pure read view of a chain's step sequence (hashes and seqs)."""
    chain_id: str
    concluded: bool
    seq: int  # seq of the read, validated, never consumed.
    # (step_no, rationale_digest, confidence, step_digest) in order.
    steps: Tuple[Tuple[int, str, float, str], ...]


@dataclass(frozen=True)
class VerifyReport:
    """Integrity report of a chain's hash linkage, as data."""
    chain_id: str
    ok: bool  # True = every step's pin recomputes and links line up.
    steps: int
    head_digest: str
    seq: int


@dataclass(frozen=True)
class ChainStats:
    """Per-chain summary as data (not a record)."""
    chain_id: str
    steps: int
    concluded: bool


class ChainOfThought:
    """Deterministic chain-of-thought reasoning ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no model calls:
    reasoning content is host-declared and pinned by digest only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._chains: Dict[str, ChainRecord] = {}
        self._steps: Dict[str, list] = {}
        self._conclusions: Dict[str, ConclusionRecord] = {}
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(chain_of_thought_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit.append(chain_of_thought_audit_event(
            audit_kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def begin(self, chain_id: object, question_digest: object,
              seq: object) -> ChainRecord:
        """Open a reasoning chain; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                chain_id = _check_chain_id(chain_id)
                question_digest = _check_digest(question_digest,
                                                "question_digest")
                if chain_id in self._chains:
                    raise DuplicateChainError(
                        f"chain already begun: {chain_id!r}")
            except ChainOfThoughtError as e:
                self._burn(seq, e)
            rec = ChainRecord(
                chain_id=chain_id, question_digest=question_digest,
                seq=seq,
                digest=_pin("chain", chain_id, question_digest, seq))
            self._chains[chain_id] = rec
            self._steps[chain_id] = []
            self._last_seq = seq
            self._emit(KIND_CHAIN_BEGUN,
                       {"chain_id": chain_id,
                        "question_digest": question_digest,
                        "digest": rec.digest}, seq)
            return rec

    def reason(self, chain_id: object, rationale_digest: object,
               confidence: object, seq: object) -> StepRecord:
        """Book one reasoning step, hash-linked to the previous step."""
        with self._lock:
            seq = self._claim(seq)
            try:
                chain_id = _check_chain_id(chain_id)
                if chain_id not in self._chains:
                    raise UnknownChainError(f"unknown chain: {chain_id!r}")
                if chain_id in self._conclusions:
                    raise ConcludedChainError(
                        f"chain already concluded: {chain_id!r}")
                rationale_digest = _check_digest(rationale_digest,
                                                 "rationale_digest")
                confidence = _check_confidence(confidence)
            except ChainOfThoughtError as e:
                self._burn(seq, e)
            booked = self._steps[chain_id]
            step_no = len(booked) + 1
            prev_digest = (booked[-1].digest if booked
                           else self._chains[chain_id].digest)
            rec = StepRecord(
                chain_id=chain_id, step_no=step_no,
                rationale_digest=rationale_digest,
                confidence=confidence, prev_digest=prev_digest, seq=seq,
                digest=_pin(
                    "step", chain_id, step_no, rationale_digest,
                    repr(_safe_confidence(confidence)), prev_digest, seq))
            booked.append(rec)
            self._last_seq = seq
            # Rationale text banned from the audit boundary: digest only.
            self._emit(KIND_STEP_REASONED,
                       {"chain_id": chain_id, "step_no": step_no,
                        "rationale_digest": rationale_digest,
                        "digest": rec.digest}, seq)
            return rec

    def conclude(self, chain_id: object, answer_digest: object,
                 seq: object) -> ConclusionRecord:
        """Terminal: book the chain's declared answer digest (exactly once)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                chain_id = _check_chain_id(chain_id)
                if chain_id not in self._chains:
                    raise UnknownChainError(f"unknown chain: {chain_id!r}")
                if chain_id in self._conclusions:
                    raise ConcludedChainError(
                        f"chain already concluded: {chain_id!r}")
                answer_digest = _check_digest(answer_digest,
                                              "answer_digest")
                booked = self._steps[chain_id]
                if not booked:
                    raise EmptyChainError(
                        f"cannot conclude a chain with zero steps: "
                        f"{chain_id!r}")
            except ChainOfThoughtError as e:
                self._burn(seq, e)
            booked = self._steps[chain_id]
            head_digest = booked[-1].digest
            rec = ConclusionRecord(
                chain_id=chain_id, answer_digest=answer_digest,
                steps=len(booked), head_digest=head_digest, seq=seq,
                digest=_pin("conclude", chain_id, answer_digest,
                            len(booked), head_digest, seq))
            self._conclusions[chain_id] = rec
            self._last_seq = seq
            # Answer text banned from the audit boundary: digest only.
            self._emit(KIND_CONCLUDED,
                       {"chain_id": chain_id, "steps": len(booked),
                        "answer_digest": answer_digest,
                        "digest": rec.digest}, seq)
            return rec

    # -- views --------------------------------------------------------------

    def chain_record(self, chain_id: str) -> Optional[ChainRecord]:
        """Return the chain record, or None when unknown (pure read)."""
        return self._chains.get(chain_id)

    def conclusion_record(self, chain_id: str) -> Optional[ConclusionRecord]:
        """Return the conclusion, or None when not concluded (pure read)."""
        return self._conclusions.get(chain_id)

    def chain_ids(self) -> Tuple[str, ...]:
        """Sorted begun chain ids (pure read)."""
        return tuple(sorted(self._chains))

    def stats(self, seq: object) -> Tuple[ChainStats, ...]:
        """Per-chain summary as data: seq validated, never consumed."""
        _check_seq(seq)
        with self._lock:
            return tuple(
                ChainStats(chain_id=cid, steps=len(self._steps[cid]),
                             concluded=cid in self._conclusions)
                for cid in sorted(self._chains))

    def trace(self, chain_id: object, seq: object) -> TraceReport:
        """Pure read view of a chain's step sequence.

        Unknown chains raise ``UnknownChainError``; the seq is validated
        but never consumed and no audit row is written.
        """
        _check_seq(seq)
        chain_id = _check_chain_id(chain_id)
        with self._lock:
            if chain_id not in self._chains:
                raise UnknownChainError(f"unknown chain: {chain_id!r}")
            steps = tuple(
                (s.step_no, s.rationale_digest, s.confidence, s.digest)
                for s in self._steps[chain_id])
            return TraceReport(
                chain_id=chain_id,
                concluded=chain_id in self._conclusions,
                seq=seq, steps=steps)

    def verify(self, chain_id: object, seq: object) -> VerifyReport:
        """Re-walk the chain's hash linkage; result is data, never raised."""
        _check_seq(seq)
        chain_id = _check_chain_id(chain_id)
        with self._lock:
            if chain_id not in self._chains:
                raise UnknownChainError(f"unknown chain: {chain_id!r}")
            expected_prev = self._chains[chain_id].digest
            ok = True
            for s in self._steps[chain_id]:
                if s.prev_digest != expected_prev or not s.verify():
                    ok = False
                    break
                expected_prev = s.digest
            head = (self._steps[chain_id][-1].digest
                    if self._steps[chain_id] else "")
            return VerifyReport(
                chain_id=chain_id, ok=ok,
                steps=len(self._steps[chain_id]), head_digest=head,
                seq=seq)

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: begin, reason (linked), conclude, trace, verify."""
    q = _pin("question", "why is the sky blue")
    r1 = _pin("rationale", "light scatters")
    r2 = _pin("rationale", "blue scatters most")
    a = _pin("answer", "rayleigh scattering")
    cot = ChainOfThought()
    ch = cot.begin("c1", q, 1)
    assert ch.verify("c1", q)
    s1 = cot.reason("c1", r1, 0.8, 2)
    assert s1.step_no == 1 and s1.prev_digest == ch.digest
    assert s1.verify()
    s2 = cot.reason("c1", r2, 0.9, 3)
    assert s2.step_no == 2 and s2.prev_digest == s1.digest
    tr = cot.trace("c1", 3)
    assert len(tr.steps) == 2 and not tr.concluded
    v = cot.verify("c1", 3)
    assert v.ok and v.steps == 2 and v.head_digest == s2.digest
    c = cot.conclude("c1", a, 4)
    assert c.verify("c1", a, 2, s2.digest)
    assert cot.trace("c1", 4).concluded
    assert len(cot.audit_log()) == 4
    # Tampered step does not verify.
    bad = StepRecord(chain_id="c1", step_no=1, rationale_digest=r1,
                     confidence=0.8, prev_digest="sha256:" + "0" * 64,
                     seq=2, digest=s1.digest)
    assert not bad.verify()
    print("chain-of-thought OK: begin, reason, trace, verify, conclude")


if __name__ == "__main__":
    main()
