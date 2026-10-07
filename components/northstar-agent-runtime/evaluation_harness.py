"""LLM eval-harness (suite/score/report) interface, simulated.

Research motivation: LLM evaluation is the "verify" half of agent
development -- LM Eval Harness, OpenAI Evals, HELM, and every vendor
bench reduce to the same ledger: declare a fixed set of test cases,
book one scoring decision per case per run, and derive the aggregate
report. Getting the bookkeeping wrong (silently rescored cases,
drifted expectations between runs, unrecorded verdict changes) voids
the comparison before any analysis runs.

This module is the *eval ledger* half of that shape:

- ``EvaluationHarness.suite(suite_id, cases, seq)`` -- declare an eval
  suite: a pinned set of ``(case_id, input_digest, expected_digest)``
  triples. Raw prompts and gold answers never enter a record -- only
  ``sha256:`` digest pins. Duplicate ids refused fail-closed; ids are
  never recycled.
- ``EvaluationHarness.score(suite_id, run_id, results, seq)`` -- book
  one host-declared scoring of every case in the suite for a run.
  Each result pins ``(case_id, passed, metric)`` where ``passed`` is a
  bool verdict and ``metric`` is a finite float in [0, 1]. Every suite
  case must be scored exactly once -- unknown or missing cases are
  refused fail-closed. This books the *verdict*, not proof the model
  ran: scores are host-reported (GIGO).
- ``EvaluationHarness.report(suite_id, run_id, seq)`` -- pure read
  view: per-case outcomes plus the aggregate -- pass count and the
  exact pass rate booked as ``"n/m"`` text (no floats), mean metric as
  an exact fraction. Verdicts are data, never raised. Validates seq
  shape, consumes nothing, writes no audit row.
- ``evaluation_harness_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``suite-registered`` / ``scored`` / ``rejected``);
  caller-supplied seqs only. Raw case text and raw scores never cross
  the audit boundary -- audit rows carry ids, counts, and digest pins
  only.

Fail-closed edges (fail loudly, never guess):

- ``suite_id`` / ``case_id`` / ``run_id`` are non-empty str, <= 256
  chars, no whitespace.
- Digests must look like ``sha256:<64 hex>`` pins.
- ``cases`` must be non-empty with unique case ids.
- ``score`` refuses unknown suites (``UnknownSuiteError``), unknown
  cases (``UnknownCaseError``), missing cases (``MissingCaseError``),
  and duplicate runs (``DuplicateRunError``).
- ``metric`` must be a finite float in [0, 1] (bool refused).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* suites and *host-reported* scores. A
  booked score is a ledger entry, not a verified measurement -- the
  module cannot prove the host ran the model, the prompt matches the
  pinned input digest, or the judge was impartial.
- ``report()`` recomputes aggregates deterministically from the
  ledger; determinism is the point: the same ledger always yields the
  same report.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if eval state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "evaluation-harness.v1"
SCHEMA = "northstar.evaluation-harness.v1"

_ID_RE = re.compile(r"^[^\s]{1,256}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUDIT_SCHEMA = "audit.ndjson/1"
_KINDS = ("suite-registered", "scored", "rejected")
# raw case material must never cross the audit boundary
_BANNED = ("input", "expected", "prompt", "gold", "answer", "text",
           "results", "result", "score", "metric", "passed", "payload",
           "raw", "value")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class EvaluationHarnessError(Exception):
    """Base error for the evaluation harness ledger."""


class BadSuiteError(EvaluationHarnessError):
    pass


class DuplicateSuiteError(EvaluationHarnessError):
    pass


class UnknownSuiteError(EvaluationHarnessError):
    pass


class BadCaseError(EvaluationHarnessError):
    pass


class DuplicateCaseError(EvaluationHarnessError):
    pass


class UnknownCaseError(EvaluationHarnessError):
    pass


class MissingCaseError(EvaluationHarnessError):
    pass


class BadRunError(EvaluationHarnessError):
    pass


class DuplicateRunError(EvaluationHarnessError):
    pass


class BadScoreError(EvaluationHarnessError):
    pass


class BadMetricError(EvaluationHarnessError):
    pass


class SeqOrderError(EvaluationHarnessError):
    pass


class AuditKindError(EvaluationHarnessError):
    pass


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

def evaluation_harness_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` audit record."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError(f"bad seq for audit: {seq!r}")
    for key in detail:
        low = key.lower()
        if low in _BANNED:
            raise BadScoreError(
                f"audit detail key {key!r} risks leaking raw eval material")
    record: Dict[str, Any] = {
        "schema": _AUDIT_SCHEMA,
        "version": VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }
    return record


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

def _digest_pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    input_digest: str
    expected_digest: str
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "input_digest": self.input_digest,
            "expected_digest": self.expected_digest,
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin("case", self.case_id,
                                          self.input_digest,
                                          self.expected_digest)


@dataclass(frozen=True)
class SuiteRecord:
    suite_id: str
    cases: Tuple[CaseSpec, ...]
    case_count: int
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "cases": [c.as_dict() for c in self.cases],
            "case_count": self.case_count,
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        if self.case_count != len(self.cases):
            return False
        if any(not c.verify() for c in self.cases):
            return False
        return self.digest == _digest_pin(
            "suite", self.suite_id,
            sorted(c.case_id for c in self.cases),
            [c.digest for c in sorted(self.cases, key=lambda c: c.case_id)])


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    passed: bool
    metric: float
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "passed": self.passed,
            "metric": self.metric,
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin("result", self.case_id,
                                          self.passed, self.metric)


@dataclass(frozen=True)
class ScoreRecord:
    suite_id: str
    run_id: str
    results: Tuple[CaseResult, ...]
    passed_count: int
    case_count: int
    pass_rate_text: str
    mean_metric_text: str
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "run_id": self.run_id,
            "results": [r.as_dict() for r in self.results],
            "passed_count": self.passed_count,
            "case_count": self.case_count,
            "pass_rate_text": self.pass_rate_text,
            "mean_metric_text": self.mean_metric_text,
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        if self.passed_count != sum(1 for r in self.results if r.passed):
            return False
        if self.case_count != len(self.results):
            return False
        if any(not r.verify() for r in self.results):
            return False
        return self.digest == _digest_pin(
            "score", self.suite_id, self.run_id,
            [r.digest for r in sorted(self.results, key=lambda r: r.case_id)])


@dataclass(frozen=True)
class ReportView:
    suite_id: str
    run_id: str
    suite_digest: str
    score_digest: str
    passed_count: int
    case_count: int
    pass_rate_text: str
    mean_metric_text: str
    per_case: Tuple[Tuple[str, bool], ...]
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "run_id": self.run_id,
            "suite_digest": self.suite_digest,
            "score_digest": self.score_digest,
            "passed_count": self.passed_count,
            "case_count": self.case_count,
            "pass_rate_text": self.pass_rate_text,
            "mean_metric_text": self.mean_metric_text,
            "per_case": [list(t) for t in self.per_case],
            "digest": self.digest,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "report", self.suite_id, self.run_id, self.suite_digest,
            self.score_digest, self.passed_count, self.case_count,
            self.pass_rate_text, self.mean_metric_text,
            list(self.per_case))


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

def _check_id(value: Any, error: Any, what: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise error(f"bad {what}: {value!r}")
    return value


def _check_digest(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise BadCaseError(f"bad {what} digest pin: {value!r}")
    return value


def _check_metric(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadMetricError(f"metric must be a number, got {value!r}")
    f = float(value)
    if not (0.0 <= f <= 1.0) or f != f:  # NaN refuses itself
        raise BadMetricError(f"metric must be in [0, 1], got {value!r}")
    return f


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


class EvaluationHarness:
    """Deterministic eval-suite/score/report ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._suites: Dict[str, SuiteRecord] = {}
        self._scores: Dict[Tuple[str, str], ScoreRecord] = {}
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        """Claim a caller seq for a mutation. Rewinds raise bare."""
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq {seq} not strictly increasing (last={self._last_seq})")
            self._last_seq = seq
            return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(evaluation_harness_audit_event(audit_kind, seq,
                                                         **detail))

    def _reject(self, seq: int, reason: str) -> None:
        self._emit("rejected", seq, reason=reason)

    # -- public API --------------------------------------------------------

    def suite(self, suite_id: str, cases: Any, seq: int) -> SuiteRecord:
        """Declare an eval suite: pinned (case_id, input, expected) triples."""
        claimed = self._claim(seq)
        try:
            suite_id = _check_id(suite_id, BadSuiteError, "suite_id")
            with self._lock:
                if suite_id in self._suites:
                    raise DuplicateSuiteError(f"duplicate suite: {suite_id!r}")
            if not isinstance(cases, (list, tuple)) or not cases:
                raise BadCaseError("cases must be a non-empty list")
            seen = set()
            specs = []
            for entry in cases:
                if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                    raise BadCaseError(f"case must be a 3-tuple, got {entry!r}")
                cid, in_d, exp_d = entry
                cid = _check_id(cid, BadCaseError, "case_id")
                if cid in seen:
                    raise DuplicateCaseError(f"duplicate case: {cid!r}")
                seen.add(cid)
                in_d = _check_digest(in_d, "input")
                exp_d = _check_digest(exp_d, "expected")
                specs.append(CaseSpec(
                    case_id=cid, input_digest=in_d, expected_digest=exp_d,
                    digest=_digest_pin("case", cid, in_d, exp_d)))
            specs.sort(key=lambda c: c.case_id)
            spec_tuple = tuple(specs)
            record = SuiteRecord(
                suite_id=suite_id, cases=spec_tuple,
                case_count=len(spec_tuple),
                digest=_digest_pin(
                    "suite", suite_id, sorted(seen),
                    [c.digest for c in spec_tuple]))
            with self._lock:
                self._suites[suite_id] = record
            self._emit("suite-registered", claimed, suite_id=suite_id,
                       case_count=len(spec_tuple), suite_digest=record.digest)
            return record
        except EvaluationHarnessError as exc:
            self._reject(claimed, type(exc).__name__)
            raise

    def score(self, suite_id: str, run_id: str, results: Any,
              seq: int) -> ScoreRecord:
        """Book one host-declared scoring of every suite case for a run."""
        claimed = self._claim(seq)
        try:
            suite_id = _check_id(suite_id, BadSuiteError, "suite_id")
            run_id = _check_id(run_id, BadRunError, "run_id")
            with self._lock:
                suite = self._suites.get(suite_id)
                if suite is None:
                    raise UnknownSuiteError(f"unknown suite: {suite_id!r}")
                if (suite_id, run_id) in self._scores:
                    raise DuplicateRunError(
                        f"duplicate run {run_id!r} for suite {suite_id!r}")
            if not isinstance(results, (list, tuple)) or not results:
                raise BadScoreError("results must be a non-empty list")
            expected = {c.case_id for c in suite.cases}
            seen = set()
            booked = []
            for entry in results:
                if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                    raise BadScoreError(
                        f"result must be a 3-tuple, got {entry!r}")
                cid, passed, metric = entry
                cid = _check_id(cid, BadScoreError, "case_id")
                if cid not in expected:
                    raise UnknownCaseError(f"unknown case: {cid!r}")
                if cid in seen:
                    raise BadScoreError(f"duplicate result for {cid!r}")
                seen.add(cid)
                if not isinstance(passed, bool):
                    raise BadScoreError(
                        f"passed must be bool, got {passed!r}")
                metric = _check_metric(metric)
                booked.append(CaseResult(
                    case_id=cid, passed=passed, metric=metric,
                    digest=_digest_pin("result", cid, passed, metric)))
            missing = sorted(expected - seen)
            if missing:
                raise MissingCaseError(f"unscored cases: {missing}")
            booked.sort(key=lambda r: r.case_id)
            booked_tuple = tuple(booked)
            passed_count = sum(1 for r in booked_tuple if r.passed)
            case_count = len(booked_tuple)
            total = sum(Fraction(r.metric).limit_denominator(10 ** 9)
                        for r in booked_tuple)
            record = ScoreRecord(
                suite_id=suite_id, run_id=run_id, results=booked_tuple,
                passed_count=passed_count, case_count=case_count,
                pass_rate_text=f"{passed_count}/{case_count}",
                mean_metric_text=f"{total.numerator}/{total.denominator}"
                                 if case_count else "0/1",
                digest=_digest_pin(
                    "score", suite_id, run_id,
                    [r.digest for r in booked_tuple]))
            # mean is total / case_count: normalize into one fraction
            if case_count:
                mean = total / case_count
                record = ScoreRecord(
                    suite_id=suite_id, run_id=run_id, results=booked_tuple,
                    passed_count=passed_count, case_count=case_count,
                    pass_rate_text=f"{passed_count}/{case_count}",
                    mean_metric_text=f"{mean.numerator}/{mean.denominator}",
                    digest=record.digest)
            with self._lock:
                self._scores[(suite_id, run_id)] = record
            self._emit("scored", claimed, suite_id=suite_id, run_id=run_id,
                       case_count=case_count, passed_count=passed_count,
                       score_digest=record.digest)
            return record
        except EvaluationHarnessError as exc:
            self._reject(claimed, type(exc).__name__)
            raise

    def report(self, suite_id: str, run_id: str, seq: int) -> ReportView:
        """Pure read view: per-case verdicts plus exact aggregates."""
        _check_seq(seq)  # validated, never consumed
        suite_id = _check_id(suite_id, BadSuiteError, "suite_id")
        run_id = _check_id(run_id, BadRunError, "run_id")
        with self._lock:
            suite = self._suites.get(suite_id)
            if suite is None:
                raise UnknownSuiteError(f"unknown suite: {suite_id!r}")
            score = self._scores.get((suite_id, run_id))
            if score is None:
                raise UnknownSuiteError(
                    f"no score booked for run {run_id!r} of {suite_id!r}")
        per_case = tuple(sorted((r.case_id, r.passed) for r in score.results))
        view = ReportView(
            suite_id=suite_id, run_id=run_id, suite_digest=suite.digest,
            score_digest=score.digest, passed_count=score.passed_count,
            case_count=score.case_count,
            pass_rate_text=score.pass_rate_text,
            mean_metric_text=score.mean_metric_text,
            per_case=per_case,
            digest=_digest_pin(
                "report", suite_id, run_id, suite.digest, score.digest,
                score.passed_count, score.case_count,
                score.pass_rate_text, score.mean_metric_text,
                list(per_case)))
        return view

    # -- views -------------------------------------------------------------

    def suite_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._suites))

    def run_ids(self, suite_id: str, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        suite_id = _check_id(suite_id, BadSuiteError, "suite_id")
        with self._lock:
            if suite_id not in self._suites:
                raise UnknownSuiteError(f"unknown suite: {suite_id!r}")
            return tuple(sorted(r for (s, r) in self._scores if s == suite_id))

    def stats(self, seq: int) -> Dict[str, Any]:
        _check_seq(seq)
        with self._lock:
            return {
                "suite_count": len(self._suites),
                "score_count": len(self._scores),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    h = EvaluationHarness()
    d1 = "sha256:" + "ab" * 32
    d2 = "sha256:" + "cd" * 32
    d3 = "sha256:" + "ef" * 32
    d4 = "sha256:" + "01" * 32
    s = h.suite("s1", [("c1", d1, d2), ("c2", d3, d4)], 0)
    assert s.verify()
    sc = h.score("s1", "r1", [("c1", True, 1.0), ("c2", False, 0.25)], 1)
    assert sc.verify()
    assert sc.pass_rate_text == "1/2"
    r = h.report("s1", "r1", 1)
    assert r.verify()
    assert r.per_case == (("c1", True), ("c2", False))
    assert len(h.audit_log(1)) == 2
    print("evaluation-harness OK: suite, score, report, pins, audit")


if __name__ == "__main__":
    main()
