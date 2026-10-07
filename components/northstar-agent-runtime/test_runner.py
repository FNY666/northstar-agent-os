"""Test runner interface (pytest-style discover/run/report, simulated).

Research motivation: CI orchestration, dev-loop harnesses, and agent
self-verification all need the same three primitives: *find the tests*
(test discovery, like pytest's collection), *run them* (a bounded
execution plan the host actually executes), and *summarize the outcome*
(aggregated pass/fail/skip/error report). The industry shape is the
same everywhere (pytest collection, JUnit XML, TAP, Bazel test logs).

This module is the *bookkeeping* half of that shape:

- ``TestRunner`` -- ``register_test()`` pins a test's identity
  (suite, name, labels); ``discover()`` lists registered tests
  matching a suite/label/name pattern; ``run()`` opens a frozen run
  plan (the ledger the host executes); ``complete_run()`` closes the
  run with host-reported per-test outcomes; ``report()`` emits a
  frozen aggregate summary (totals, pass rate, per-suite breakdown).
- ``test_runner_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``test-registered`` / ``discovered`` / ``run-started`` /
  ``run-completed`` / ``report-emitted`` / ``rejected``);
  caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``suite_name`` and ``test_id`` are non-empty ``str``; ``labels``
  are lowercase word tokens; caller seqs are ints (not bool) and
  must be strictly increasing per runner instance. A failed mutation
  still consumes its seq (fail-closed ledger position).
- Duplicate ``test_id`` registration is refused
  (``DuplicateTestError``); unknown ids are refused, never invented.
- ``run()`` refuses an empty test set (an empty run plan is a lie of
  omission) and refuses duplicate in-flight runs on overlapping test
  sets... precisely: a run plan is opened with a frozen, pinned
  test-id list; completing it twice is refused (``TerminalRunError``).
- ``complete_run()`` requires an outcome for *every* planned test
  (``IncompleteRunError`` on partial results) and refuses outcomes
  for tests not in the plan (``PlanMismatchError``).
- Outcomes are pinned to the vocabulary
  ``{"pass", "fail", "skip", "error"}``; ``duration_ms`` is a
  non-negative int (not bool); error text is capped at 4 KiB.

Honest scope:

- This module is simulated: it cannot execute code, fork processes,
  or observe real test outcomes. ``complete_run()`` pins
  host-reported outcomes -- a ``pass`` means "the host said it
  passed", never "the code is correct" (GIGO boundary). Pair with an
  attested executor for production trust.
- Digests bind record identity and plan membership, never
  behavioral truth.
- In-memory only: pair with the durable audit writer if run history
  must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

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
TEST_RUNNER_VERSION = "test-runner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.test-runner.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned outcome vocabulary (pytest/JUnit shaped).
OUTCOMES: Tuple[str, ...] = ("pass", "fail", "skip", "error")

#: Max error text stored per test outcome (guardrail).
MAX_ERROR_CHARS = 4096

#: Label token pattern.
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class TestRunnerError(ValueError):
    """Base fail-closed test-runner error."""


class DuplicateTestError(TestRunnerError):
    """A test_id was registered twice."""


class UnknownTestError(TestRunnerError):
    """A test_id was never registered."""


class UnknownRunError(TestRunnerError):
    """A run_id was never opened."""


class EmptyPlanError(TestRunnerError):
    """run() was called with an empty test set."""


class TerminalRunError(TestRunnerError):
    """A completed run was completed again."""


class IncompleteRunError(TestRunnerError):
    """complete_run() outcomes did not cover the whole plan."""


class PlanMismatchError(TestRunnerError):
    """An outcome named a test outside the run plan."""


class BadOutcomeError(TestRunnerError):
    """An outcome was not in the pinned vocabulary."""


class ValidationError(TestRunnerError):
    """Malformed ids, labels, durations, or error text."""


class SeqOrderError(TestRunnerError):
    """Caller seqs were not strictly increasing ints (not bool)."""


def _pin(obj: Any) -> str:
    return "sha256:" + jcs_sha256_hex(obj)


def _check_seq(seq: Any) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-bool non-negative int, got {seq!r}")


def _check_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty str, got {value!r}")
    return value


def _check_labels(labels: Any) -> Tuple[str, ...]:
    if labels is None:
        return ()
    if not isinstance(labels, (list, tuple)):
        raise ValidationError(f"labels must be a list/tuple, got {labels!r}")
    out = []
    for label in labels:
        if not isinstance(label, str) or not _LABEL_RE.match(label):
            raise ValidationError(f"bad label token: {label!r}")
        if label not in out:
            out.append(label)
    return tuple(out)


@dataclass(frozen=True)
class TestRecord:
    """A registered test's pinned identity."""
    test_id: str
    suite: str
    labels: Tuple[str, ...]
    timeout_ms: Optional[int]
    pin: str
    version: str = TEST_RUNNER_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id, "suite": self.suite,
            "labels": list(self.labels), "timeout_ms": self.timeout_ms,
            "pin": self.pin, "version": self.version,
        }


@dataclass(frozen=True)
class DiscoveryReport:
    """Frozen result of a discover() call."""
    pattern: str
    suite: Optional[str]
    label: Optional[str]
    test_ids: Tuple[str, ...]
    count: int
    pin: str
    version: str = TEST_RUNNER_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern, "suite": self.suite,
            "label": self.label, "test_ids": list(self.test_ids),
            "count": self.count, "pin": self.pin, "version": self.version,
        }


@dataclass(frozen=True)
class RunPlan:
    """A frozen run plan opened by run()."""
    run_id: str
    test_ids: Tuple[str, ...]
    started_seq: int
    pin: str
    status: str = "started"
    version: str = TEST_RUNNER_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id, "test_ids": list(self.test_ids),
            "started_seq": self.started_seq, "pin": self.pin,
            "status": self.status, "version": self.version,
        }


@dataclass(frozen=True)
class TestOutcome:
    """One host-reported per-test outcome."""
    test_id: str
    outcome: str
    duration_ms: int
    error: Optional[str]
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id, "outcome": self.outcome,
            "duration_ms": self.duration_ms, "error": self.error,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class RunReport:
    """Frozen aggregate summary of a completed run."""
    run_id: str
    total: int
    passed: int
    failed: int
    skipped: int
    errors: int
    pass_rate_bp: int  # basis points, exact int math
    outcomes: Tuple[TestOutcome, ...]
    per_suite: Tuple[Tuple[str, int, int], ...]  # (suite, total, passed)
    pin: str
    version: str = TEST_RUNNER_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id, "total": self.total,
            "passed": self.passed, "failed": self.failed,
            "skipped": self.skipped, "errors": self.errors,
            "pass_rate_bp": self.pass_rate_bp,
            "outcomes": [o.as_dict() for o in self.outcomes],
            "per_suite": [list(s) for s in self.per_suite],
            "pin": self.pin, "version": self.version,
        }


class TestRunner:
    """pytest-shaped test discovery/run/report bookkeeping (simulated)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tests: Dict[str, TestRecord] = {}
        self._runs: Dict[str, RunPlan] = {}
        self._reports: Dict[str, RunReport] = {}
        self._completed: set = set()
        self._run_seq = 0
        self._last_seq = -1
        self._audit: list = []

    # -- internal -----------------------------------------------------
    def _consume_seq(self, seq: Any) -> None:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._last_seq}"
            )
        self._last_seq = seq  # failed mutations consume their seq too

    def _audit_event(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        event = {
            "schema": AUDIT_SCHEMA,
            "module": SCHEMA_PIN,
            "kind": kind,
            "seq": seq,
            "detail": dict(detail),
        }
        event["pin"] = _pin(event)
        self._audit.append(event)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(e) for e in self._audit)

    # -- registration --------------------------------------------------
    def register_test(self, test_id: str, suite: str, seq: int,
                      labels: Optional[Sequence[str]] = None,
                      timeout_ms: Optional[int] = None) -> TestRecord:
        """Pin a test's identity. Duplicate ids are refused."""
        with self._lock:
            self._consume_seq(seq)
            test_id = _check_str(test_id, "test_id")
            suite = _check_str(suite, "suite")
            lab = _check_labels(labels)
            if timeout_ms is not None:
                if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) \
                        or timeout_ms <= 0:
                    raise ValidationError(f"bad timeout_ms: {timeout_ms!r}")
            if test_id in self._tests:
                raise DuplicateTestError(f"duplicate test_id: {test_id!r}")
            record = TestRecord(
                test_id=test_id, suite=suite, labels=lab,
                timeout_ms=timeout_ms,
                pin=_pin({"t": "test", "id": test_id, "suite": suite,
                          "labels": list(lab), "timeout_ms": timeout_ms}),
            )
            self._tests[test_id] = record
            self._audit_event("test-registered", seq, {"test_id": test_id, "pin": record.pin})
            return record

    # -- discovery -----------------------------------------------------
    def discover(self, seq: int, pattern: str = "",
                 suite: Optional[str] = None,
                 label: Optional[str] = None) -> DiscoveryReport:
        """List registered tests matching suite/label/name substring.

        A pure view: consumes no run budget, but still pins the result.
        """
        with self._lock:
            self._consume_seq(seq)
            if not isinstance(pattern, str):
                raise ValidationError(f"pattern must be str, got {pattern!r}")
            if suite is not None:
                suite = _check_str(suite, "suite")
            if label is not None:
                label = _check_str(label, "label")
            matched = [
                tid for tid, rec in sorted(self._tests.items())
                if (suite is None or rec.suite == suite)
                and (label is None or label in rec.labels)
                and (pattern in tid)
            ]
            report = DiscoveryReport(
                pattern=pattern, suite=suite, label=label,
                test_ids=tuple(matched), count=len(matched),
                pin=_pin({"t": "discover", "pattern": pattern,
                          "suite": suite, "label": label,
                          "ids": matched}),
            )
            self._audit_event("discovered", seq,
                              {"count": len(matched), "pin": report.pin})
            return report

    # -- run ------------------------------------------------------------
    def run(self, test_ids: Sequence[str], seq: int) -> RunPlan:
        """Open a frozen run plan over a pinned test-id list."""
        with self._lock:
            self._consume_seq(seq)
            if not isinstance(test_ids, (list, tuple)) or not test_ids:
                raise EmptyPlanError("run() requires a non-empty test list")
            ids = tuple(test_ids)
            for tid in ids:
                if not isinstance(tid, str) or tid not in self._tests:
                    raise UnknownTestError(f"unknown test_id: {tid!r}")
            if len(set(ids)) != len(ids):
                raise ValidationError("duplicate test_ids in run plan")
            self._run_seq += 1
            run_id = f"run-{self._run_seq}"
            plan = RunPlan(
                run_id=run_id, test_ids=ids, started_seq=seq,
                pin=_pin({"t": "run", "id": run_id, "ids": list(ids), "seq": seq}),
            )
            self._runs[run_id] = plan
            self._audit_event("run-started", seq,
                              {"run_id": run_id, "count": len(ids), "pin": plan.pin})
            return plan

    # -- completion -----------------------------------------------------
    def complete_run(self, run_id: str, outcomes: Mapping[str, Mapping[str, Any]],
                     seq: int) -> RunReport:
        """Close a run with host-reported per-test outcomes (simulated).

        ``outcomes`` maps test_id -> {"outcome": ..., "duration_ms": ...,
        "error": ...}. Every planned test must be covered, exactly once.
        """
        with self._lock:
            self._consume_seq(seq)
            run_id = _check_str(run_id, "run_id")
            plan = self._runs.get(run_id)
            if plan is None:
                raise UnknownRunError(f"unknown run_id: {run_id!r}")
            if run_id in self._completed:
                raise TerminalRunError(f"run already completed: {run_id!r}")
            if not isinstance(outcomes, Mapping):
                raise ValidationError("outcomes must be a mapping")
            planned = set(plan.test_ids)
            given = set(outcomes.keys())
            if given != planned:
                missing = planned - given
                extra = given - planned
                if extra:
                    raise PlanMismatchError(f"outcomes for unplanned tests: {sorted(extra)}")
                raise IncompleteRunError(f"missing outcomes for: {sorted(missing)}")
            outcome_recs = []
            for tid in plan.test_ids:
                raw = outcomes[tid]
                if not isinstance(raw, Mapping):
                    raise ValidationError(f"bad outcome shape for {tid!r}")
                outcome = raw.get("outcome")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"bad outcome for {tid!r}: {outcome!r}")
                duration = raw.get("duration_ms", 0)
                if isinstance(duration, bool) or not isinstance(duration, int) \
                        or duration < 0:
                    raise ValidationError(f"bad duration_ms for {tid!r}: {duration!r}")
                error = raw.get("error")
                if error is not None:
                    if not isinstance(error, str):
                        raise ValidationError(f"bad error for {tid!r}")
                    error = error[:MAX_ERROR_CHARS]
                rec = TestOutcome(
                    test_id=tid, outcome=outcome, duration_ms=duration,
                    error=error,
                    pin=_pin({"t": "outcome", "run": run_id, "id": tid,
                              "outcome": outcome, "duration_ms": duration,
                              "error": error}),
                )
                outcome_recs.append(rec)
            passed = sum(1 for o in outcome_recs if o.outcome == "pass")
            failed = sum(1 for o in outcome_recs if o.outcome == "fail")
            skipped = sum(1 for o in outcome_recs if o.outcome == "skip")
            errors = sum(1 for o in outcome_recs if o.outcome == "error")
            total = len(outcome_recs)
            pass_rate_bp = (passed * 10000) // total  # exact int math
            suite_tot: Dict[str, Tuple[int, int]] = {}
            for rec in outcome_recs:
                suite = self._tests[rec.test_id].suite
                t, p = suite_tot.get(suite, (0, 0))
                suite_tot[suite] = (t + 1, p + (1 if rec.outcome == "pass" else 0))
            per_suite = tuple((s, t, p) for s, (t, p) in sorted(suite_tot.items()))
            report = RunReport(
                run_id=run_id, total=total, passed=passed, failed=failed,
                skipped=skipped, errors=errors, pass_rate_bp=pass_rate_bp,
                outcomes=tuple(outcome_recs), per_suite=per_suite,
                pin=_pin({"t": "report", "run": run_id, "total": total,
                          "passed": passed, "failed": failed,
                          "skipped": skipped, "errors": errors,
                          "pins": [o.pin for o in outcome_recs]}),
            )
            self._reports[run_id] = report
            self._completed.add(run_id)
            self._audit_event("run-completed", seq,
                              {"run_id": run_id, "passed": passed,
                               "total": total, "pin": report.pin})
            return report

    # -- report ----------------------------------------------------------
    def report(self, run_id: str, seq: int) -> RunReport:
        """Read back the frozen aggregate summary of a completed run."""
        with self._lock:
            self._consume_seq(seq)
            run_id = _check_str(run_id, "run_id")
            rep = self._reports.get(run_id)
            if rep is None:
                raise UnknownRunError(f"no completed report for {run_id!r}")
            self._audit_event("report-emitted", seq,
                              {"run_id": run_id, "pin": rep.pin})
            return rep

    # -- views -------------------------------------------------------------
    def test_record(self, test_id: str) -> TestRecord:
        with self._lock:
            rec = self._tests.get(test_id)
            if rec is None:
                raise UnknownTestError(f"unknown test_id: {test_id!r}")
            return rec

    def test_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tests))

    def run_plan(self, run_id: str) -> RunPlan:
        with self._lock:
            plan = self._runs.get(run_id)
            if plan is None:
                raise UnknownRunError(f"unknown run_id: {run_id!r}")
            return plan


def test_runner_audit_event(kind: str, seq: int,
                             detail: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Build a standalone audit.ndjson/1 event for test_runner."""
    valid = {"test-registered", "discovered", "run-started",
             "run-completed", "report-emitted", "rejected"}
    if kind not in valid:
        raise ValidationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA, "module": SCHEMA_PIN, "kind": kind,
        "seq": seq, "detail": dict(detail or {}),
    }
    event["pin"] = _pin(event)
    return event


def main() -> None:
    runner = TestRunner()
    runner.register_test("test_a", "unit", 1, labels=["fast"])
    runner.register_test("test_b", "unit", 2, labels=["slow"])
    runner.register_test("test_c", "integration", 3)
    disc = runner.discover(4, suite="unit")
    assert disc.count == 2
    plan = runner.run(list(disc.test_ids), 5)
    rep = runner.complete_run(plan.run_id, {
        "test_a": {"outcome": "pass", "duration_ms": 3},
        "test_b": {"outcome": "fail", "duration_ms": 7, "error": "boom"},
    }, 6)
    assert rep.total == 2 and rep.passed == 1 and rep.failed == 1
    assert rep.pass_rate_bp == 5000
    back = runner.report(plan.run_id, 7)
    assert back.pin == rep.pin
    print("test-runner OK: register, discover, run, complete, report")


if __name__ == "__main__":
    main()
