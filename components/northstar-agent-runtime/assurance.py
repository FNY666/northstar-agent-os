"""Assurance-case (argue/verify/maintain) interface, simulated.

Research motivation: assurance cases (GSN -- Goal Structuring Notation,
ISO/IEC 15026, and the assurance-case lineage used across aviation,
medical, and increasingly AI safety work) all reduce to the same ledger:
declare claims, book arguments linking sub-claims to parent claims under a
pinned strategy vocabulary, bind evidence by digest, derive structural
support, and book periodic maintenance reviews. Getting the bookkeeping
wrong (cyclic arguments, undeclared premises, raw claim text leaking into
audit rows, silent digest drift) corrupts the case before any safety
argument runs.

This module is the *decision ledger* half of that shape:

- ``Assurance.goal(goal_id, claim_digest, seq)`` -- declare one claim.
  The claim text is pinned by ``sha256:`` digest only; raw text never
  enters a record. Returns a frozen ``GoalRecord`` with a digest pin.
  Duplicate ids are refused fail-closed; ids are never recycled.
- ``Assurance.argue(strategy_id, conclusion_id, premise_ids, kind, seq)``
  -- book one argument: the premises support the conclusion, under the
  pinned strategy-kind vocabulary. Cycles and self-reference are refused
  fail-closed at book time. Returns a frozen ``ArgumentRecord``.
- ``Assurance.evidence(evidence_id, goal_id, ev_kind, artifact_digest,
  seq)`` -- bind one evidence item (a GSN "solution") to a goal.
  Artifacts are pinned by digest only. Returns a frozen
  ``EvidenceRecord``.
- ``Assurance.verify(goal_id, seq)`` -- pure read view: recomputes every
  digest pin in the goal's case graph (integrity as data, ``ok`` bool)
  and derives structural support (a goal is supported iff it carries
  evidence or has an argument whose every premise is supported). Gaps are
  data, never raised. Validates seq shape, consumes nothing, writes no
  audit row. Returns a frozen ``VerifyReport``.
- ``Assurance.maintain(goal_id, seq, reason="scheduled-review")`` -- book
  one maintenance review decision under the pinned reason vocabulary.
  Returns a frozen ``MaintainRecord`` with a minted ``mnt-N`` id.
- ``assurance_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``goal-declared`` / ``argument-booked`` / ``evidence-bound`` /
  ``maintained`` / ``rejected``); caller-supplied seqs only. Raw claim
  text never crosses the audit boundary -- audit rows carry ids, kinds,
  counts, and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``goal_id`` / ``strategy_id`` / ``evidence_id`` must be non-empty str,
  <= 256 chars, no whitespace.
- ``claim_digest`` / ``artifact_digest`` must be ``sha256:``-prefixed
  digest pins (raw claim text and raw evidence never enter records).
- ``premise_ids`` must name declared goals, be non-empty, contain no
  duplicates, and must not include the conclusion (no self-reference).
- An argument whose conclusion is already reachable from any premise
  would close a cycle -- refused fail-closed (``CycleError``).
- ``kind`` must name the pinned strategy vocabulary; ``ev_kind`` the
  pinned evidence vocabulary; ``reason`` the pinned reason vocabulary.
- Duplicate and retired ids are refused; ids are never recycled.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit row;
  seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* claims, arguments, and *host-reported*
  evidence bindings. A booked argument is a ledger entry, not a proof
  the claim is true -- claim truth is GIGO: the module judges structural
  support only (evidence bound, premises argued), never the content of a
  digest it cannot see.
- ``verify()`` recomputes digest pins and walks the declared graph; it
  cannot verify that evidence is genuine or that a claim digest was
  honestly computed.
- ``maintain()`` books a declared review decision, not proof a review
  happened.
- No persistence: the ledger is in-memory. Pair with the durable audit
  writer if assurance state must survive a restart.
"""

from __future__ import annotations

import hashlib
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

    def jcs_sha256_hex(obj):  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
ASSURANCE_VERSION = "assurance.v1"

#: Schema pin carried by records and audit events.
ASSURANCE_SCHEMA = "northstar.assurance.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned strategy-kind vocabulary (GSN argument inference rules).
STRATEGY_DECOMPOSITION = "decomposition"
STRATEGY_ENUMERATION = "enumeration"
STRATEGY_FORMAL_PROOF = "formal-proof"
STRATEGY_PROBABILISTIC = "probabilistic"
STRATEGY_EMPIRICAL = "empirical"
STRATEGY_PROCESS_ASSURANCE = "process-assurance"
STRATEGY_KINDS = (STRATEGY_DECOMPOSITION, STRATEGY_ENUMERATION,
                  STRATEGY_FORMAL_PROOF, STRATEGY_PROBABILISTIC,
                  STRATEGY_EMPIRICAL, STRATEGY_PROCESS_ASSURANCE)

#: Pinned evidence-kind vocabulary (GSN solutions).
EVIDENCE_TEST_RESULT = "test-result"
EVIDENCE_FORMAL_PROOF = "formal-proof"
EVIDENCE_REVIEW_RECORD = "review-record"
EVIDENCE_AUDIT_LOG = "audit-log"
EVIDENCE_INSPECTION = "inspection"
EVIDENCE_SIMULATION = "simulation"
EVIDENCE_STATIC_ANALYSIS = "static-analysis"
EVIDENCE_MODEL_CHECKING = "model-checking"
EVIDENCE_RUNTIME_MONITOR = "runtime-monitor"
EVIDENCE_KINDS = (EVIDENCE_TEST_RESULT, EVIDENCE_FORMAL_PROOF,
                  EVIDENCE_REVIEW_RECORD, EVIDENCE_AUDIT_LOG,
                  EVIDENCE_INSPECTION, EVIDENCE_SIMULATION,
                  EVIDENCE_STATIC_ANALYSIS, EVIDENCE_MODEL_CHECKING,
                  EVIDENCE_RUNTIME_MONITOR)

#: Pinned maintenance-reason vocabulary.
REASON_SCHEDULED_REVIEW = "scheduled-review"
REASON_POST_CHANGE = "post-change"
REASON_INCIDENT = "incident"
REASON_MANUAL = "manual"
REASON_EVIDENCE_UPDATE = "evidence-update"
REASONS = (REASON_SCHEDULED_REVIEW, REASON_POST_CHANGE, REASON_INCIDENT,
           REASON_MANUAL, REASON_EVIDENCE_UPDATE)

#: Audit event kinds.
KIND_GOAL_DECLARED = "goal-declared"
KIND_ARGUMENT_BOOKED = "argument-booked"
KIND_EVIDENCE_BOUND = "evidence-bound"
KIND_MAINTAINED = "maintained"
KIND_REJECTED = "rejected"
_KINDS = (KIND_GOAL_DECLARED, KIND_ARGUMENT_BOOKED, KIND_EVIDENCE_BOUND,
          KIND_MAINTAINED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"claim", "text", "payload", "raw", "value", "data", "variables",
     "evidence"})

#: Max id length.
_MAX_ID_LEN = 256


class AssuranceError(Exception):
    """Base error for the assurance-case ledger (programming errors)."""


class BadGoalError(AssuranceError):
    """Raised when a goal id is malformed."""


class DuplicateGoalError(AssuranceError):
    """Raised when a goal id is declared twice."""


class UnknownGoalError(AssuranceError):
    """Raised when a goal id names no declared goal."""


class BadStrategyError(AssuranceError):
    """Raised when a strategy id or premise list is malformed."""


class DuplicateStrategyError(AssuranceError):
    """Raised when a strategy id is booked twice."""


class CycleError(AssuranceError):
    """Raised when an argument would close a cycle in the case graph."""


class BadStrategyKindError(AssuranceError):
    """Raised when a strategy kind is outside the pinned vocabulary."""


class BadEvidenceError(AssuranceError):
    """Raised when an evidence id or digest is malformed."""


class DuplicateEvidenceError(AssuranceError):
    """Raised when an evidence id is bound twice."""


class BadEvidenceKindError(AssuranceError):
    """Raised when an evidence kind is outside the pinned vocabulary."""


class BadReasonError(AssuranceError):
    """Raised when a maintenance reason is outside the pinned vocabulary."""


class SeqOrderError(AssuranceError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AssuranceError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value, name="seq"):
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value, name, error_cls):
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise error_cls(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise error_cls(f"{name} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise error_cls(f"{name} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise error_cls(f"{name} must not contain whitespace")
    return value


def _check_digest(digest, name, error_cls):
    """Validate a digest pin: 'sha256:'-prefixed."""
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise error_cls(f"{name} must be str, got {type(digest).__name__}")
    if not digest.startswith("sha256:") or len(digest) <= len("sha256:"):
        raise error_cls(f"{name} must be a sha256:-prefixed digest pin")
    return digest


def _check_strategy_kind(kind):
    """Validate a strategy kind against the pinned vocabulary."""
    if kind not in STRATEGY_KINDS:
        raise BadStrategyKindError(
            f"strategy kind must be one of {list(STRATEGY_KINDS)}, "
            f"got {kind!r}")
    return kind


def _check_evidence_kind(ev_kind):
    """Validate an evidence kind against the pinned vocabulary."""
    if ev_kind not in EVIDENCE_KINDS:
        raise BadEvidenceKindError(
            f"evidence kind must be one of {list(EVIDENCE_KINDS)}, "
            f"got {ev_kind!r}")
    return ev_kind


def _check_reason(reason):
    """Validate a maintenance reason against the pinned vocabulary."""
    if reason not in REASONS:
        raise BadReasonError(
            f"reason must be one of {list(REASONS)}, got {reason!r}")
    return reason


def _pin(*parts):
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": ASSURANCE_SCHEMA,
        "parts": list(parts),
    })


def assurance_audit_event(kind, detail, seq):
    """Build one ``audit.ndjson/1`` audit row for the assurance ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": ASSURANCE_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class GoalRecord:
    """Frozen record of a declared assurance claim (GSN goal)."""
    goal_id: str
    claim_digest: str
    seq: int
    digest: str

    def verify(self, claim_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("goal", self.goal_id, claim_digest,
                                   self.seq)


@dataclass(frozen=True)
class ArgumentRecord:
    """Frozen record of one booked argument (premises => conclusion)."""
    strategy_id: str
    conclusion_id: str
    premise_ids: Tuple[str, ...]
    strategy_kind: str
    seq: int
    digest: str

    def verify(self, conclusion_id, premise_ids, strategy_kind):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "argument", self.strategy_id, conclusion_id,
            list(premise_ids), strategy_kind, self.seq)


@dataclass(frozen=True)
class EvidenceRecord:
    """Frozen record of one evidence item bound to a goal (GSN solution)."""
    evidence_id: str
    goal_id: str
    ev_kind: str
    artifact_digest: str
    seq: int
    digest: str

    def verify(self, goal_id, ev_kind, artifact_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evidence", self.evidence_id, goal_id, ev_kind,
            artifact_digest, self.seq)


@dataclass(frozen=True)
class MaintainRecord:
    """Frozen record of one maintenance review decision."""
    maintain_id: str
    goal_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, goal_id, reason):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("maintain", self.maintain_id, goal_id,
                                   reason, self.seq)


@dataclass(frozen=True)
class VerifyReport:
    """Frozen result of ``Assurance.verify``: integrity + support as data."""
    goal_id: str
    ok: bool
    supported: bool
    gaps: Tuple[str, ...]
    goals_checked: int
    digest: str


class Assurance:
    """Assurance-case decision ledger (GSN-shaped), deterministic."""

    def __init__(self):
        self._lock = threading.RLock()
        self._goals: Dict[str, GoalRecord] = {}
        self._strategies: Dict[str, ArgumentRecord] = {}
        self._by_conclusion: Dict[str, Tuple[str, ...]] = {}
        self._evidence: Dict[str, EvidenceRecord] = {}
        self._by_goal: Dict[str, Tuple[str, ...]] = {}
        self._maintains: Dict[str, MaintainRecord] = {}
        self._audit = []
        self._last_seq = 0
        self._maintain_n = 0

    # -- seq discipline -----------------------------------------------------

    def _claim(self, seq):
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq, error):
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(assurance_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind, detail, seq):
        self._audit.append(assurance_audit_event(audit_kind, detail, seq))

    # -- derived state (internal) --------------------------------------------

    def _reachable(self, start_id):
        """Goal ids reachable below start_id via argument edges."""
        seen = set()
        stack = [start_id]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for sid in self._by_conclusion.get(cur, ()):
                for pid in self._strategies[sid].premise_ids:
                    if pid not in seen:
                        stack.append(pid)
        return seen

    def _supported_locked(self, goal_id, memo):
        """Structural support: evidence or a fully-supported argument."""
        if goal_id in memo:
            return memo[goal_id]
        memo[goal_id] = False  # defensive: graph is cycle-free by booking rule
        if self._by_goal.get(goal_id):
            memo[goal_id] = True
            return True
        for sid in self._by_conclusion.get(goal_id, ()):
            rec = self._strategies[sid]
            if all(self._supported_locked(p, memo) for p in rec.premise_ids):
                memo[goal_id] = True
                return True
        return False

    # -- mutations ----------------------------------------------------------

    def goal(self, goal_id, claim_digest, seq):
        """Declare one assurance claim; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(goal_id, "goal_id", BadGoalError)
                _check_digest(claim_digest, "claim_digest", BadGoalError)
                if goal_id in self._goals:
                    raise DuplicateGoalError(
                        f"goal_id already declared: {goal_id!r}")
            except AssuranceError as e:
                self._burn(seq, e)
            digest = _pin("goal", goal_id, claim_digest, seq)
            rec = GoalRecord(goal_id=goal_id, claim_digest=claim_digest,
                             seq=seq, digest=digest)
            self._goals[goal_id] = rec
            self._emit(KIND_GOAL_DECLARED,
                       {"goal_id": goal_id, "claim_digest": claim_digest}, seq)
            self._last_seq = seq
            return rec

    def argue(self, strategy_id, conclusion_id, premise_ids, kind, seq):
        """Book one argument (premises => conclusion); cycles refused."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(strategy_id, "strategy_id", BadStrategyError)
                _check_id(conclusion_id, "conclusion_id", BadStrategyError)
                _check_strategy_kind(kind)
                if isinstance(premise_ids, (str, bytes)) or not isinstance(
                        premise_ids, (tuple, list)):
                    raise BadStrategyError(
                        "premise_ids must be a tuple/list of goal ids")
                premise_ids = tuple(premise_ids)
                if not premise_ids:
                    raise BadStrategyError("premise_ids must not be empty")
                for pid in premise_ids:
                    _check_id(pid, "premise_id", BadStrategyError)
                    if pid not in self._goals:
                        raise UnknownGoalError(
                            f"premise goal not declared: {pid!r}")
                if len(set(premise_ids)) != len(premise_ids):
                    raise BadStrategyError(
                        "premise_ids must not contain duplicates")
                if conclusion_id in premise_ids:
                    raise CycleError(
                        "conclusion must not appear among its own premises")
                if conclusion_id not in self._goals:
                    raise UnknownGoalError(
                        f"conclusion goal not declared: {conclusion_id!r}")
                if strategy_id in self._strategies:
                    raise DuplicateStrategyError(
                        f"strategy_id already booked: {strategy_id!r}")
                for pid in premise_ids:
                    if conclusion_id in self._reachable(pid):
                        raise CycleError(
                            f"argument {strategy_id!r} would close a cycle "
                            f"via premise {pid!r}")
            except AssuranceError as e:
                self._burn(seq, e)
            digest = _pin("argument", strategy_id, conclusion_id,
                          list(premise_ids), kind, seq)
            rec = ArgumentRecord(strategy_id=strategy_id,
                                 conclusion_id=conclusion_id,
                                 premise_ids=premise_ids, strategy_kind=kind,
                                 seq=seq, digest=digest)
            self._strategies[strategy_id] = rec
            self._by_conclusion[conclusion_id] = (
                self._by_conclusion.get(conclusion_id, ()) + (strategy_id,))
            self._emit(KIND_ARGUMENT_BOOKED,
                       {"strategy_id": strategy_id,
                        "conclusion_id": conclusion_id,
                        "premise_ids": list(premise_ids),
                        "strategy_kind": kind}, seq)
            self._last_seq = seq
            return rec

    def evidence(self, evidence_id, goal_id, ev_kind, artifact_digest, seq):
        """Bind one evidence item to a goal; digest-pinned only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(evidence_id, "evidence_id", BadEvidenceError)
                _check_id(goal_id, "goal_id", BadEvidenceError)
                _check_evidence_kind(ev_kind)
                _check_digest(artifact_digest, "artifact_digest",
                              BadEvidenceError)
                if goal_id not in self._goals:
                    raise UnknownGoalError(
                        f"goal not declared: {goal_id!r}")
                if evidence_id in self._evidence:
                    raise DuplicateEvidenceError(
                        f"evidence_id already bound: {evidence_id!r}")
            except AssuranceError as e:
                self._burn(seq, e)
            digest = _pin("evidence", evidence_id, goal_id, ev_kind,
                          artifact_digest, seq)
            rec = EvidenceRecord(evidence_id=evidence_id, goal_id=goal_id,
                                 ev_kind=ev_kind,
                                 artifact_digest=artifact_digest, seq=seq,
                                 digest=digest)
            self._evidence[evidence_id] = rec
            self._by_goal[goal_id] = (
                self._by_goal.get(goal_id, ()) + (evidence_id,))
            self._emit(KIND_EVIDENCE_BOUND,
                       {"evidence_id": evidence_id, "goal_id": goal_id,
                        "ev_kind": ev_kind,
                        "artifact_digest": artifact_digest}, seq)
            self._last_seq = seq
            return rec

    def maintain(self, goal_id, seq, reason=REASON_SCHEDULED_REVIEW):
        """Book one maintenance review decision for a goal."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(goal_id, "goal_id", BadGoalError)
                _check_reason(reason)
                if goal_id not in self._goals:
                    raise UnknownGoalError(
                        f"goal not declared: {goal_id!r}")
            except AssuranceError as e:
                self._burn(seq, e)
            self._maintain_n += 1
            maintain_id = f"mnt-{self._maintain_n}"
            digest = _pin("maintain", maintain_id, goal_id, reason, seq)
            rec = MaintainRecord(maintain_id=maintain_id, goal_id=goal_id,
                                 reason=reason, seq=seq, digest=digest)
            self._maintains[maintain_id] = rec
            self._emit(KIND_MAINTAINED,
                       {"maintain_id": maintain_id, "goal_id": goal_id,
                        "reason": reason}, seq)
            self._last_seq = seq
            return rec

    # -- pure reads (seq validated, never consumed, no audit rows) -----------

    def verify(self, goal_id, seq):
        """Verify a goal's case graph: pin integrity + support, as data."""
        with self._lock:
            _check_id(goal_id, "goal_id", BadGoalError)
            _check_seq(seq)
            if goal_id not in self._goals:
                raise UnknownGoalError(f"goal not declared: {goal_id!r}")
            graph = self._reachable(goal_id)
            ok = True
            for gid in graph:
                grec = self._goals[gid]
                if not grec.verify(grec.claim_digest):
                    ok = False
                for sid in self._by_conclusion.get(gid, ()):
                    srec = self._strategies[sid]
                    if not srec.verify(srec.conclusion_id, srec.premise_ids,
                                       srec.strategy_kind):
                        ok = False
                for eid in self._by_goal.get(gid, ()):
                    erec = self._evidence[eid]
                    if not erec.verify(erec.goal_id, erec.ev_kind,
                                       erec.artifact_digest):
                        ok = False
            memo: Dict[str, bool] = {}
            supported = self._supported_locked(goal_id, memo)
            gaps = tuple(sorted(g for g in graph
                                if not self._supported_locked(g, memo)))
            digest = _pin("verify", goal_id, ok, supported, list(gaps))
            return VerifyReport(goal_id=goal_id, ok=ok, supported=supported,
                                gaps=gaps, goals_checked=len(graph),
                                digest=digest)

    def goal_record(self, goal_id, seq):
        """Read one declared goal (pure read)."""
        with self._lock:
            _check_id(goal_id, "goal_id", BadGoalError)
            _check_seq(seq)
            if goal_id not in self._goals:
                raise UnknownGoalError(f"goal not declared: {goal_id!r}")
            return self._goals[goal_id]

    def goal_ids(self, seq):
        """Sorted declared goal ids (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._goals))

    def evidence_ids(self, seq):
        """Sorted bound evidence ids (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._evidence))

    def maintain_ids(self, seq):
        """Sorted maintenance-record ids (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._maintains))

    def audit_log(self, seq):
        """Read-only copy of the audit rows (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq):
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "goals": len(self._goals),
                "strategies": len(self._strategies),
                "evidence": len(self._evidence),
                "maintains": len(self._maintains),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }


def main():
    """Self-check smoke run."""
    a = Assurance()
    top = a.goal("g-top", "sha256:" + "0" * 64, 1)
    assert top.verify("sha256:" + "0" * 64)
    a.goal("g-a", "sha256:" + "1" * 64, 2)
    a.goal("g-b", "sha256:" + "2" * 64, 3)
    a.argue("s-1", "g-top", ("g-a", "g-b"), "decomposition", 4)
    a.evidence("e-1", "g-a", "test-result", "sha256:" + "3" * 64, 5)
    a.evidence("e-2", "g-b", "inspection", "sha256:" + "4" * 64, 6)
    rep = a.verify("g-top", 7)
    assert rep.ok and rep.supported and rep.gaps == (), rep
    m = a.maintain("g-top", 8)
    assert m.maintain_id == "mnt-1"
    # fail-closed spot checks (one fresh instance to keep seqs simple)
    b = Assurance()
    for bad_seq in (True, "9", -1, 1.5, None):
        try:
            b.goal("g-x", "sha256:" + "5" * 64, bad_seq)
            raise AssertionError(f"bad seq accepted: {bad_seq!r}")
        except SeqOrderError:
            pass
    b.goal("g-1", "sha256:" + "6" * 64, 1)
    try:
        b.goal("g-1", "sha256:" + "7" * 64, 2)
        raise AssertionError("duplicate goal accepted")
    except DuplicateGoalError:
        pass
    try:
        b.argue("s-1", "g-1", ("g-1",), "decomposition", 3)
        raise AssertionError("self-reference accepted")
    except CycleError:
        pass
    try:
        b.argue("s-1", "g-1", ("g-1", "g-1"), "decomposition", 4)
        raise AssertionError("duplicate premises accepted")
    except BadStrategyError:
        pass
    # cycle across two arguments: g-1 <= g-2, then g-2 <= g-1 refused
    b.goal("g-2", "sha256:" + "8" * 64, 5)
    b.argue("s-1", "g-1", ("g-2",), "decomposition", 6)
    try:
        b.argue("s-2", "g-2", ("g-1",), "decomposition", 7)
        raise AssertionError("cycle accepted")
    except CycleError:
        pass
    print("assurance OK: goal, argue, evidence, verify, maintain, pins, audit")


if __name__ == "__main__":
    main()
