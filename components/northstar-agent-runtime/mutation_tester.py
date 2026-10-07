"""Mutation tester interface (mutmut-style, simulated).

Research motivation: coverage tells an agent *which lines ran*; mutation
testing tells it *which lines matter*. The industry shape is the same
everywhere (mutmut, Stryker, PIT, Cosmic Ray): apply small syntactic
transformations (mutants) to the source under test, re-run the suite,
and count how many mutants the tests *kill*. A mutant the suite cannot
kill is either a weak test or dead code -- either way the ledger entry
is worth reading.

This module is the *bookkeeping* half of that shape:

- ``MutationTester`` -- ``register_target()`` pins a host-reported
  source snapshot (ordered lines); ``mutate()`` walks the lines and
  applies a pinned operator table (``arith-op``, ``compare``,
  ``bool-lit``, ``int-lit``, ``stmt-delete``), emitting one frozen
  ``MutantRecord`` per (line, operator) that changes the text;
  ``kill()`` records a host-reported kill (mutant_id + the test that
  killed it); ``survive()`` records a host-reported survivor;
  ``score()`` computes the mutation score as an exact ``Fraction``
  (killed / (killed + survived)) -- untested mutants are excluded,
  never counted as survivors.
- ``mutation_tester_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``target-registered`` / ``mutated`` / ``killed`` /
  ``survived`` / ``scored`` / ``rejected``); caller-supplied seqs
  only. Source lines never cross the audit boundary.

Fail-closed edges (fail loudly, never guess):

- ``target_id`` / ``mutant_id`` / ``test_id`` are non-empty ``str``;
  ``source_lines`` is a non-empty list/tuple of ``str`` (blank lines
  are skipped by ``mutate()``, never mutated); operator names must be
  in the pinned ``OPERATORS`` vocabulary; caller seqs are ints (not
  bool), non-negative, and strictly increasing per tester instance.
  A failed mutation still consumes its seq (fail-closed ledger
  position).
- ``mutate()`` on an unknown target raises ``UnknownTargetError``;
  ``kill()`` / ``survive()`` on an unknown mutant raises
  ``UnknownMutantError``; a second verdict on the same mutant raises
  ``DuplicateVerdictError`` -- a mutant is killed *or* survives,
  never both, never twice.
- Mutation score is exact integer math (``Fraction``), so pins never
  see a float. ``score()`` with no decided mutants reports
  ``score=None`` (no evidence), not ``0`` (a lie).

Honest scope:

- This module books *reported* mutation testing. The "source" is
  host-asserted text lines; the mutants are deterministic text
  transforms; ``kill()`` / ``survive()`` pin the host's test-outcome
  claims. It runs no tests, executes no code, and cannot prove a
  mutant is truly dead (GIGO boundary). Pair with a real runner
  (e.g. mutmut) plus a pinned source digest for production use.
- In-memory only: pair with the durable audit writer if mutant
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
MUTATION_TESTER_VERSION = "mutation-tester.v1"

#: Schema pin carried by records and audit events.
MUTATION_TESTER_SCHEMA = "northstar.mutation-tester.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"


# ---------------------------------------------------------------------------
# Pinned operator table (mutmut lineage).
# ---------------------------------------------------------------------------

#: Arithmetic operator swap pairs (first occurrence wins).
ARITH_PAIRS = {"+": "-", "-": "+", "*": "/", "/": "*"}

#: Comparison inversion pairs, longest token first so ``<=`` is not read as ``<``.
COMPARE_PAIRS = (
    ("==", "!="),
    ("!=", "=="),
    ("<=", ">"),
    (">=", "<"),
    ("<", ">="),
    (">", "<="),
)

#: Boolean literal inversion.
BOOL_PAIRS = {"True": "False", "False": "True"}

#: Pinned operator vocabulary, in application order.
OPERATORS = ("arith-op", "compare", "bool-lit", "int-lit", "stmt-delete")

#: Marker placed in ``mutated_line`` for statement-deletion mutants.
STMT_DELETE_MARKER = "<deleted>"

_INT_LIT_RE = re.compile(r"\b\d+\b")
_BOOL_LIT_RE = re.compile(r"\b(True|False)\b")


def _apply_operator(operator: str, line: str) -> Optional[str]:
    """Return the mutated line, or ``None`` when the operator does not apply."""
    if operator == "arith-op":
        for i, ch in enumerate(line):
            if ch in ARITH_PAIRS:
                return line[:i] + ARITH_PAIRS[ch] + line[i + 1:]
        return None
    if operator == "compare":
        for old, new in COMPARE_PAIRS:
            idx = line.find(old)
            if idx != -1:
                return line[:idx] + new + line[idx + len(old):]
        return None
    if operator == "bool-lit":
        m = _BOOL_LIT_RE.search(line)
        if m:
            word = m.group(1)
            return line[:m.start()] + BOOL_PAIRS[word] + line[m.end():]
        return None
    if operator == "int-lit":
        m = _INT_LIT_RE.search(line)
        if m:
            return line[:m.start()] + str(int(m.group(0)) + 1) + line[m.end():]
        return None
    if operator == "stmt-delete":
        return STMT_DELETE_MARKER if line.strip() else None
    return None  # unreachable: operator vocabulary validated at mutate() time


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed).
# ---------------------------------------------------------------------------

class MutationError(ValueError):
    """Base for all mutation-tester errors."""


class UnknownTargetError(MutationError):
    """Target id is not registered."""


class DuplicateTargetError(MutationError):
    """Target id is already registered (ids are never recycled)."""


class UnknownMutantError(MutationError):
    """Mutant id is unknown."""


class DuplicateVerdictError(MutationError):
    """Mutant already has a kill/survive verdict (verdicts are terminal)."""


class UnknownOperatorError(MutationError):
    """Operator name is not in the pinned vocabulary."""


class SeqOrderError(MutationError):
    """Caller seq is not a strictly increasing non-bool int."""


class ValidationError(MutationError):
    """Malformed id, lines, test id, or detail payload."""


# ---------------------------------------------------------------------------
# Frozen records.
# ---------------------------------------------------------------------------

def _pin(*parts: Any) -> str:
    """sha256: pin over a type-tagged canonical body (bool != int != str)."""
    def tag(v: Any) -> Any:
        if isinstance(v, bool):
            return ("bool", v)
        if isinstance(v, int):
            return ("int", v)
        if isinstance(v, str):
            return ("str", v)
        if v is None:
            return ("none",)
        if isinstance(v, (tuple, list)):
            return ("list", [tag(x) for x in v])
        raise ValidationError(f"unpinable value: {v!r}")
    return "sha256:" + jcs_sha256_hex([tag(p) for p in parts])


@dataclass(frozen=True)
class TargetRecord:
    """Pinned source snapshot under test."""
    target_id: str
    line_count: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"target_id": self.target_id, "line_count": self.line_count,
                "digest": self.digest}

    def verify(self, source_lines: Tuple[str, ...]) -> bool:
        """Re-derive the pin from the registered lines."""
        return self.digest == _pin("target", self.target_id, list(source_lines))


@dataclass(frozen=True)
class MutantRecord:
    """One deterministic (line, operator) mutant."""
    mutant_id: str
    target_id: str
    line_no: int  # 1-based
    operator: str
    original_line: str
    mutated_line: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"mutant_id": self.mutant_id, "target_id": self.target_id,
                "line_no": self.line_no, "operator": self.operator,
                "original_line": self.original_line,
                "mutated_line": self.mutated_line, "digest": self.digest}

    def verify(self) -> bool:
        """Re-derive the digest pin (tamper -> False)."""
        return self.digest == _pin("mutant", self.mutant_id, self.target_id,
                                   self.line_no, self.operator,
                                   self.original_line, self.mutated_line)


@dataclass(frozen=True)
class KillRecord:
    """A host-reported kill: this test failed on this mutant."""
    kill_id: str
    mutant_id: str
    test_id: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"kill_id": self.kill_id, "mutant_id": self.mutant_id,
                "test_id": self.test_id, "digest": self.digest}


@dataclass(frozen=True)
class SurviveRecord:
    """A host-reported survivor: the suite passed on this mutant."""
    survive_id: str
    mutant_id: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"survive_id": self.survive_id, "mutant_id": self.mutant_id,
                "digest": self.digest}


@dataclass(frozen=True)
class MutationScore:
    """Exact mutation score over decided mutants (untested excluded)."""
    score_id: str
    total: int
    killed: int
    survived: int
    untested: int
    score_num: Optional[int]  # None when no mutant has a verdict
    score_den: Optional[int]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"score_id": self.score_id, "total": self.total,
                "killed": self.killed, "survived": self.survived,
                "untested": self.untested,
                "score": (f"{self.score_num}/{self.score_den}"
                          if self.score_num is not None else None),
                "digest": self.digest}

    def fraction(self) -> Optional[Fraction]:
        """Exact score, or None when no mutant has a verdict."""
        if self.score_num is None or self.score_den is None:
            return None
        return Fraction(self.score_num, self.score_den)


# ---------------------------------------------------------------------------
# The tester.
# ---------------------------------------------------------------------------

class MutationTester:
    """Deterministic mutant ledger: register, mutate, kill, survive, score."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: Optional[int] = None
        self._targets: Dict[str, Tuple[str, ...]] = {}
        self._mutants: Dict[str, MutantRecord] = {}
        self._kills: Dict[str, KillRecord] = {}          # mutant_id -> kill
        self._survivors: Dict[str, SurviveRecord] = {}   # mutant_id -> survive
        self._mutant_seq = 0
        self._kill_seq = 0
        self._survive_seq = 0
        self._score_seq = 0

    # -- seq discipline ----------------------------------------------------

    def _claim_seq(self, seq: Any) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
        if self._last_seq is not None and seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})")
        self._last_seq = seq  # consumed even when the mutation below fails

    @staticmethod
    def _check_id(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{name} must be a non-empty str")
        return value

    # -- targets ------------------------------------------------------------

    def register_target(self, target_id: str, source_lines: Any,
                        seq: int) -> TargetRecord:
        """Pin a host-reported source snapshot (ordered lines)."""
        with self._lock:
            self._claim_seq(seq)
            target_id = self._check_id(target_id, "target_id")
            if target_id in self._targets:
                raise DuplicateTargetError(f"target already registered: {target_id}")
            if not isinstance(source_lines, (list, tuple)) or not source_lines:
                raise ValidationError("source_lines must be a non-empty list/tuple")
            lines: List[str] = []
            for ln in source_lines:
                if not isinstance(ln, str):
                    raise ValidationError("every source line must be a str")
                lines.append(ln)
            frozen = tuple(lines)
            self._targets[target_id] = frozen
            return TargetRecord(target_id=target_id, line_count=len(frozen),
                                digest=_pin("target", target_id, lines))

    # -- mutation ------------------------------------------------------------

    def mutate(self, target_id: str, seq: int,
               operators: Any = None) -> Tuple[MutantRecord, ...]:
        """Generate mutants for a registered target (ids monotonic)."""
        with self._lock:
            self._claim_seq(seq)
            target_id = self._check_id(target_id, "target_id")
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id}")
            if operators is None:
                ops = OPERATORS
            else:
                if not isinstance(operators, (list, tuple)) or not operators:
                    raise ValidationError("operators must be a non-empty list/tuple")
                for op in operators:
                    if op not in OPERATORS:
                        raise UnknownOperatorError(f"unknown operator: {op!r}")
                ops = tuple(operators)
            lines = self._targets[target_id]
            out: List[MutantRecord] = []
            for line_no, line in enumerate(lines, start=1):
                for op in ops:
                    mutated = _apply_operator(op, line)
                    if mutated is None or mutated == line:
                        continue
                    self._mutant_seq += 1
                    mid = f"mut-{self._mutant_seq}"
                    rec = MutantRecord(
                        mutant_id=mid, target_id=target_id, line_no=line_no,
                        operator=op, original_line=line, mutated_line=mutated,
                        digest=_pin("mutant", mid, target_id, line_no, op,
                                    line, mutated))
                    self._mutants[mid] = rec
                    out.append(rec)
            return tuple(out)

    # -- verdicts ------------------------------------------------------------

    def kill(self, mutant_id: str, seq: int, test_id: str) -> KillRecord:
        """Record a host-reported kill: ``test_id`` failed on this mutant."""
        with self._lock:
            self._claim_seq(seq)
            mutant_id = self._check_id(mutant_id, "mutant_id")
            test_id = self._check_id(test_id, "test_id")
            if mutant_id not in self._mutants:
                raise UnknownMutantError(f"unknown mutant: {mutant_id}")
            if mutant_id in self._kills or mutant_id in self._survivors:
                raise DuplicateVerdictError(
                    f"mutant already has a verdict: {mutant_id}")
            self._kill_seq += 1
            kid = f"kill-{self._kill_seq}"
            rec = KillRecord(kill_id=kid, mutant_id=mutant_id, test_id=test_id,
                             digest=_pin("kill", kid, mutant_id, test_id))
            self._kills[mutant_id] = rec
            return rec

    def survive(self, mutant_id: str, seq: int) -> SurviveRecord:
        """Record a host-reported survivor: the suite passed on this mutant."""
        with self._lock:
            self._claim_seq(seq)
            mutant_id = self._check_id(mutant_id, "mutant_id")
            if mutant_id not in self._mutants:
                raise UnknownMutantError(f"unknown mutant: {mutant_id}")
            if mutant_id in self._kills or mutant_id in self._survivors:
                raise DuplicateVerdictError(
                    f"mutant already has a verdict: {mutant_id}")
            self._survive_seq += 1
            sid = f"sur-{self._survive_seq}"
            rec = SurviveRecord(survive_id=sid, mutant_id=mutant_id,
                                digest=_pin("survive", sid, mutant_id))
            self._survivors[mutant_id] = rec
            return rec

    # -- scoring -------------------------------------------------------------

    def score(self, seq: int) -> MutationScore:
        """Exact mutation score over decided mutants (untested excluded)."""
        with self._lock:
            self._claim_seq(seq)
            total = len(self._mutants)
            killed = len(self._kills)
            survived = len(self._survivors)
            untested = total - killed - survived
            decided = killed + survived
            if decided:
                frac = Fraction(killed, decided)
                num, den = frac.numerator, frac.denominator
            else:
                num, den = None, None
            self._score_seq += 1
            sid = f"score-{self._score_seq}"
            digest = _pin("score", sid, total, killed, survived, untested,
                          num if num is not None else -1,
                          den if den is not None else -1)
            return MutationScore(score_id=sid, total=total, killed=killed,
                                 survived=survived, untested=untested,
                                 score_num=num, score_den=den, digest=digest)

    # -- views (pure, no seq consumed) ---------------------------------------

    def target(self, target_id: str) -> TargetRecord:
        with self._lock:
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id}")
            lines = self._targets[target_id]
            return TargetRecord(target_id=target_id, line_count=len(lines),
                                digest=_pin("target", target_id, list(lines)))

    def target_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._targets))

    def mutant(self, mutant_id: str) -> MutantRecord:
        with self._lock:
            if mutant_id not in self._mutants:
                raise UnknownMutantError(f"unknown mutant: {mutant_id}")
            return self._mutants[mutant_id]

    def mutant_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._mutants,
                                key=lambda m: int(m.split("-")[1])))

    def mutants_of(self, target_id: str) -> Tuple[MutantRecord, ...]:
        with self._lock:
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id}")
            return tuple(m for m in self._mutants.values()
                         if m.target_id == target_id)

    def verdict(self, mutant_id: str) -> Optional[str]:
        """'killed', 'survived', or None (untested)."""
        with self._lock:
            if mutant_id not in self._mutants:
                raise UnknownMutantError(f"unknown mutant: {mutant_id}")
            if mutant_id in self._kills:
                return "killed"
            if mutant_id in self._survivors:
                return "survived"
            return None


# ---------------------------------------------------------------------------
# Audit events.
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("target-registered", "mutated", "killed", "survived",
                "scored", "rejected")


@dataclass(frozen=True)
class MutationTesterAuditEvent:
    kind: str
    seq: int
    detail: Mapping[str, Any]
    schema: str = AUDIT_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "seq": self.seq,
                "detail": dict(self.detail), "schema": self.schema}


def mutation_tester_audit_event(kind: str, seq: int,
                                detail: Mapping[str, Any]
                                ) -> MutationTesterAuditEvent:
    """Build an ``audit.ndjson/1`` record (ids/pins only, never source lines)."""
    if kind not in _AUDIT_KINDS:
        raise ValidationError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"audit seq must be a non-negative int, got {seq!r}")
    if not isinstance(detail, Mapping):
        raise ValidationError("audit detail must be a mapping")
    for banned in ("source_lines", "original_line", "mutated_line", "payload"):
        if banned in detail:
            raise ValidationError(
                f"audit detail must not carry raw source ({banned})")
    return MutationTesterAuditEvent(kind=kind, seq=seq, detail=dict(detail))


# ---------------------------------------------------------------------------
# Self-check.
# ---------------------------------------------------------------------------

def main() -> None:
    t = MutationTester()
    t.register_target("t1", ["x = a + b", "if x == 1:", "flag = True"], seq=1)
    mutants = t.mutate("t1", seq=2)
    assert len(mutants) >= 3, f"expected >=3 mutants, got {len(mutants)}"
    assert all(m.verify() for m in mutants)
    t.kill(mutants[0].mutant_id, seq=3, test_id="test_add")
    t.survive(mutants[1].mutant_id, seq=4)
    s = t.score(seq=5)
    assert s.killed == 1 and s.survived == 1
    assert s.fraction() == Fraction(1, 2)
    assert s.untested == len(mutants) - 2
    ev = mutation_tester_audit_event("scored", 5, {"score_id": s.score_id})
    assert ev.schema == AUDIT_SCHEMA
    print("mutation-tester OK: register, mutate, kill, survive, score, audit")


if __name__ == "__main__":
    main()
