"""Load tester: k6-style virtual-user scenario bookkeeping, simulated.

Research note: *load testing* measures how a system behaves under demand
before production does. k6 (Grafana) runs *virtual users* (VUs) executing a
scripted scenario against a target: ``stages`` ramp the VU count over time
(e.g. ``[{duration: "30s", target: 20}]``), each iteration records latency
and a pass/fail, and *thresholds* assert SLOs over the aggregate
(``p(95)<500``, ``http_req_failed<0.01``); a run fails if any threshold
breaks. Locust drives user classes with wait times; Gatling uses injection
profiles (at-once, ramp, constant rate). The common core is: *scenario
plan* -> *executed iterations* -> *aggregate metrics* -> *threshold
verdict*.

This module is that core as deterministic, network-free bookkeeping:

* **Scenario plan** — :meth:`LoadTester.define` pins an ordered list of
  :class:`ScenarioStage` records (``duration_seqs`` x ``target_vus``);
  durations are caller-supplied logical seqs, never wall-clock seconds, so
  plans are audit-replay exact.
* **Execution** — :meth:`LoadTester.run` aggregates per-iteration
  ``(latency_ms, ok)`` samples. The host may supply measured samples, or
  omit them and get the deterministic built-in simulator: a per-scenario
  HMAC-SHA256 stream keyed by caller seed, so identical
  ``(scenario, seed)`` pairs always produce identical runs.
* **Aggregation** — every :class:`RunReport` carries total/ok/error counts,
  error rate, min/avg/max and p50/p95/p99 latencies (nearest-rank), and a
  ``sha256:`` digest pin binding the whole report.
* **Thresholds** — :meth:`LoadTester.check` evaluates k6-shaped threshold
  expressions over ``p95_ms`` / ``p99_ms`` / ``avg_ms`` / ``error_rate``
  with ``<`` / ``<=`` / ``>`` / ``>=`` operators, returning a frozen
  :class:`ThresholdReport` naming each threshold's pass/fail.
* **Fail-closed** — unknown scenario/run ids, duplicate scenario ids,
  malformed stages, non-bool ``ok`` flags, NaN latencies, and unknown
  threshold metrics/operators all raise; nothing silently degrades to a
  vacuous "all green".

Honest scope: this is *decision bookkeeping*, not a load generator — the
simulator's latencies are hash-derived fiction and even host-supplied
samples are *reported* numbers this module never measured. It can prove
"this plan produced these aggregates and these threshold verdicts", never
"the target will hold this load". For ground truth, run real k6/Locust
against the target and feed the measured samples to :meth:`run`.

Version pin: load-tester.v1
Schema pin: northstar.load-tester.v1
"""

from __future__ import annotations

import hashlib
import hmac
import math
import threading
from dataclasses import dataclass
from typing import Any

#: Module version.
LOAD_TESTER_VERSION = "load-tester.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.load-tester.v1"

#: Metrics a threshold may assert on.
THRESHOLD_METRICS = ("p95_ms", "p99_ms", "avg_ms", "error_rate")

#: Comparison operators a threshold may use.
THRESHOLD_OPS = ("<", "<=", ">", ">=")

#: Fail-closed ceiling on simulator iterations per run.
MAX_SIM_ITERATIONS = 1_000_000

#: Audit event kinds emitted by this module.
AUDIT_KINDS = (
    "scenario-defined",
    "run-completed",
    "thresholds-checked",
    "rejected",
)


class LoadTesterError(Exception):
    """Malformed use of the load tester (programming error)."""


class DuplicateScenarioError(LoadTesterError):
    """A scenario id was defined twice."""


class UnknownScenarioError(LoadTesterError):
    """Operation on a scenario id that was never defined."""


class UnknownRunError(LoadTesterError):
    """Operation on a run id that was never recorded."""


class TooManyIterationsError(LoadTesterError):
    """The simulator plan exceeds the fail-closed iteration ceiling."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise LoadTesterError(f"{what} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise LoadTesterError(f"{what} must be non-negative, got {seq}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise LoadTesterError(f"{what} must be a non-empty str, got {value!r}")
    return value


def _check_stage(value: Any) -> "ScenarioStage":
    if isinstance(value, ScenarioStage):
        return value
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return ScenarioStage(duration_seqs=value[0], target_vus=value[1])
    raise LoadTesterError(
        f"stage must be a ScenarioStage or (duration_seqs, target_vus) pair, "
        f"got {value!r}"
    )


def _check_stages(stages: Any) -> tuple:
    if isinstance(stages, (str, bytes)) or not isinstance(stages, (tuple, list)):
        raise LoadTesterError(
            f"stages must be a non-empty sequence, got {type(stages).__name__}"
        )
    checked = tuple(_check_stage(s) for s in stages)
    if not checked:
        raise LoadTesterError("stages must be non-empty")
    return checked


def _check_latency(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LoadTesterError(
            f"latency_ms must be a number, got {type(value).__name__}"
        )
    value = float(value)
    if not math.isfinite(value):
        raise LoadTesterError(f"latency_ms must be finite, got {value}")
    if value < 0.0:
        raise LoadTesterError(f"latency_ms must be non-negative, got {value}")
    return value


def _check_samples(samples: Any) -> tuple:
    if isinstance(samples, (str, bytes)) or not isinstance(samples, (tuple, list)):
        raise LoadTesterError(
            f"samples must be a sequence of (latency_ms, ok) pairs, "
            f"got {type(samples).__name__}"
        )
    checked = []
    for s in samples:
        if not isinstance(s, (tuple, list)) or len(s) != 2:
            raise LoadTesterError(f"sample must be a (latency_ms, ok) pair, got {s!r}")
        latency, ok = s
        if not isinstance(ok, bool):
            raise LoadTesterError(
                f"sample ok flag must be a bool, got {type(ok).__name__}"
            )
        checked.append((_check_latency(latency), ok))
    return tuple(checked)


def _check_seed(seed: Any) -> bytes:
    if not isinstance(seed, (bytes, bytearray)):
        raise LoadTesterError(f"seed must be bytes, got {type(seed).__name__}")
    return bytes(seed)


def _check_thresholds(thresholds: Any) -> dict:
    if not isinstance(thresholds, dict) or not thresholds:
        raise LoadTesterError("thresholds must be a non-empty mapping")
    checked = {}
    for name, spec in thresholds.items():
        if name not in THRESHOLD_METRICS:
            raise LoadTesterError(
                f"unknown threshold metric {name!r}; must be one of {THRESHOLD_METRICS}"
            )
        if not isinstance(spec, (tuple, list)) or len(spec) != 2:
            raise LoadTesterError(
                f"threshold {name!r} must be an (op, bound) pair, got {spec!r}"
            )
        op, bound = spec
        if op not in THRESHOLD_OPS:
            raise LoadTesterError(
                f"unknown threshold op {op!r}; must be one of {THRESHOLD_OPS}"
            )
        bound = _check_latency(bound)
        checked[name] = (op, bound)
    return checked


def _digest(*parts: str) -> str:
    body = "\x1f".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _percentile(sorted_values: tuple, pct: float) -> float:
    """Nearest-rank percentile over ascending sorted values."""
    if not sorted_values:
        return 0.0
    rank = math.ceil(pct / 100.0 * len(sorted_values))
    return sorted_values[max(0, min(rank - 1, len(sorted_values) - 1))]


@dataclass(frozen=True)
class ScenarioStage:
    """One ramp stage: ``target_vus`` virtual users for ``duration_seqs``."""

    duration_seqs: int
    target_vus: int

    def __post_init__(self) -> None:
        for name, value in (("duration_seqs", self.duration_seqs),
                            ("target_vus", self.target_vus)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise LoadTesterError(
                    f"{name} must be an int, got {type(value).__name__}"
                )
            if value < 0:
                raise LoadTesterError(f"{name} must be non-negative, got {value}")

    def as_dict(self) -> dict:
        return {
            "duration_seqs": self.duration_seqs,
            "target_vus": self.target_vus,
        }


@dataclass(frozen=True)
class ScenarioDefinition:
    """A pinned scenario plan (frozen record)."""

    version: str
    scenario_id: str
    stages: tuple
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "scenario_id": self.scenario_id,
            "stages": [s.as_dict() for s in self.stages],
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RunReport:
    """Aggregated metrics for one run (frozen record)."""

    version: str
    run_id: str
    scenario_id: str
    seq: int
    total_requests: int
    ok_count: int
    error_count: int
    error_rate: float
    min_ms: float
    avg_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "seq": self.seq,
            "total_requests": self.total_requests,
            "ok_count": self.ok_count,
            "error_count": self.error_count,
            "error_rate": self.error_rate,
            "min_ms": self.min_ms,
            "avg_ms": self.avg_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "digest": self.digest,
        }

    def metric(self, name: str) -> float:
        """Look up an aggregatable metric by threshold name."""
        if name == "p95_ms":
            return self.p95_ms
        if name == "p99_ms":
            return self.p99_ms
        if name == "avg_ms":
            return self.avg_ms
        if name == "error_rate":
            return self.error_rate
        raise LoadTesterError(f"unknown metric {name!r}")


@dataclass(frozen=True)
class ThresholdResult:
    """One threshold's verdict (frozen record)."""

    name: str
    op: str
    bound: float
    actual: float
    passed: bool

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "op": self.op,
            "bound": self.bound,
            "actual": self.actual,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class ThresholdReport:
    """Threshold verdicts for one run (frozen record)."""

    version: str
    run_id: str
    seq: int
    results: tuple
    passed: bool
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "run_id": self.run_id,
            "seq": self.seq,
            "results": [r.as_dict() for r in self.results],
            "passed": self.passed,
            "digest": self.digest,
        }


class LoadTester:
    """k6-style scenario ledger with a deterministic simulated executor.

    Scenarios are pinned at define time; runs aggregate host-supplied or
    simulated samples; thresholds judge the aggregates. All state advances
    on caller-supplied int seqs (no wall-clock).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scenarios: dict = {}
        self._runs: dict = {}
        self._run_seq = 0

    def define(self, scenario_id: str, stages: Any, seq: int) -> ScenarioDefinition:
        """Pin a scenario plan. Duplicate ids are refused fail-closed."""
        scenario_id = _check_id(scenario_id, "scenario_id")
        checked = _check_stages(stages)
        seq = _check_seq(seq)
        with self._lock:
            if scenario_id in self._scenarios:
                raise DuplicateScenarioError(
                    f"scenario {scenario_id!r} already defined"
                )
            stage_body = ",".join(
                f"{s.duration_seqs}:{s.target_vus}" for s in checked
            )
            digest = _digest(scenario_id, stage_body, str(seq))
            definition = ScenarioDefinition(
                version=LOAD_TESTER_VERSION,
                scenario_id=scenario_id,
                stages=checked,
                seq=seq,
                digest=digest,
            )
            self._scenarios[scenario_id] = definition
            return definition

    def scenario_ids(self) -> tuple:
        """Defined scenario ids in definition order."""
        with self._lock:
            return tuple(self._scenarios)

    def run(
        self,
        scenario_id: str,
        seq: int,
        samples: Any = None,
        seed: bytes = b"",
    ) -> RunReport:
        """Execute a scenario and pin the aggregate report.

        ``samples`` is a host-supplied sequence of ``(latency_ms, ok)``
        pairs. When omitted, the deterministic simulator generates them
        from the stage plan under ``seed``.
        """
        scenario_id = _check_id(scenario_id, "scenario_id")
        seq = _check_seq(seq)
        seed = _check_seed(seed)
        with self._lock:
            definition = self._scenarios.get(scenario_id)
            if definition is None:
                raise UnknownScenarioError(
                    f"scenario {scenario_id!r} is not defined"
                )
            if samples is None:
                latencies = self._simulate(definition, seed)
            else:
                latencies = _check_samples(samples)
            self._run_seq += 1
            run_id = f"run-{self._run_seq}"
            report = self._aggregate(run_id, scenario_id, seq, latencies)
            self._runs[run_id] = report
            return report

    def _simulate(
        self, definition: ScenarioDefinition, seed: bytes
    ) -> tuple:
        """Deterministic hash-stream samples from the stage plan."""
        total = sum(s.duration_seqs * s.target_vus for s in definition.stages)
        if total > MAX_SIM_ITERATIONS:
            raise TooManyIterationsError(
                f"plan needs {total} iterations, ceiling is {MAX_SIM_ITERATIONS}"
            )
        key = seed + definition.digest.encode("utf-8")
        samples = []
        for stage_idx, stage in enumerate(definition.stages):
            iterations = stage.duration_seqs * stage.target_vus
            for i in range(iterations):
                msg = f"{stage_idx}:{i}".encode("utf-8")
                stream = hmac.new(key, msg, hashlib.sha256).digest()
                latency = 50.0 + (int.from_bytes(stream[:8], "big") % 451)
                ok = (int.from_bytes(stream[8:16], "big") % 100) != 0
                samples.append((latency, ok))
        return tuple(samples)

    @staticmethod
    def _aggregate(
        run_id: str, scenario_id: str, seq: int, samples: tuple
    ) -> RunReport:
        total = len(samples)
        ok_count = sum(1 for _, ok in samples if ok)
        error_count = total - ok_count
        error_rate = (error_count / total) if total else 0.0
        latencies = tuple(sorted(lat for lat, _ in samples))
        if latencies:
            min_ms = latencies[0]
            max_ms = latencies[-1]
            avg_ms = math.fsum(latencies) / total
            p50 = _percentile(latencies, 50.0)
            p95 = _percentile(latencies, 95.0)
            p99 = _percentile(latencies, 99.0)
        else:
            min_ms = max_ms = avg_ms = p50 = p95 = p99 = 0.0
        digest = _digest(
            run_id,
            scenario_id,
            str(seq),
            str(total),
            str(ok_count),
            repr(avg_ms),
            repr(p95),
            repr(p99),
            repr(error_rate),
        )
        return RunReport(
            version=LOAD_TESTER_VERSION,
            run_id=run_id,
            scenario_id=scenario_id,
            seq=seq,
            total_requests=total,
            ok_count=ok_count,
            error_count=error_count,
            error_rate=error_rate,
            min_ms=min_ms,
            avg_ms=avg_ms,
            p50_ms=p50,
            p95_ms=p95,
            p99_ms=p99,
            max_ms=max_ms,
            digest=digest,
        )

    def report(self, run_id: str) -> RunReport:
        """Fetch a pinned run report. Unknown ids raise fail-closed."""
        run_id = _check_id(run_id, "run_id")
        with self._lock:
            report = self._runs.get(run_id)
            if report is None:
                raise UnknownRunError(f"run {run_id!r} is not recorded")
            return report

    def runs(self) -> tuple:
        """Run ids in execution order."""
        with self._lock:
            return tuple(self._runs)

    def check(self, run_id: str, thresholds: Any, seq: int) -> ThresholdReport:
        """Evaluate k6-shaped thresholds against a run's aggregates."""
        run_id = _check_id(run_id, "run_id")
        checked = _check_thresholds(thresholds)
        seq = _check_seq(seq)
        with self._lock:
            report = self._runs.get(run_id)
            if report is None:
                raise UnknownRunError(f"run {run_id!r} is not recorded")
            results = []
            for name in sorted(checked):
                op, bound = checked[name]
                actual = report.metric(name)
                if op == "<":
                    passed = actual < bound
                elif op == "<=":
                    passed = actual <= bound
                elif op == ">":
                    passed = actual > bound
                else:
                    passed = actual >= bound
                results.append(
                    ThresholdResult(
                        name=name, op=op, bound=bound, actual=actual, passed=passed
                    )
                )
            overall = all(r.passed for r in results)
            body = ",".join(
                f"{r.name}{r.op}{r.bound}={r.passed}" for r in results
            )
            digest = _digest(run_id, body, str(seq))
            return ThresholdReport(
                version=LOAD_TESTER_VERSION,
                run_id=run_id,
                seq=seq,
                results=tuple(results),
                passed=overall,
                digest=digest,
            )


def load_tester_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for a load-tester event."""
    if kind not in AUDIT_KINDS:
        raise LoadTesterError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    if not isinstance(detail, dict):
        raise LoadTesterError("detail must be a dict")
    event = {
        "schema": "northstar.audit.ndjson/1",
        "module": LOAD_TESTER_VERSION,
        "event": kind,
        "audit_seq": seq,
    }
    event.update(detail)
    return event


def main() -> None:
    """Self-check: define, run, aggregate, thresholds, fail-closed paths."""
    lt = LoadTester()
    assert lt.scenario_ids() == ()

    definition = lt.define("smoke", [ScenarioStage(2, 3), (1, 4)], 0)
    assert definition.digest.startswith("sha256:")
    assert lt.scenario_ids() == ("smoke",)

    # host-supplied samples: exact aggregates
    samples = [(100.0, True), (200.0, True), (300.0, False), (400.0, True)]
    report = lt.run("smoke", 1, samples=samples)
    assert report.run_id == "run-1"
    assert report.total_requests == 4
    assert report.ok_count == 3
    assert report.error_count == 1
    assert report.error_rate == 0.25
    assert report.min_ms == 100.0
    assert report.max_ms == 400.0
    assert report.avg_ms == 250.0
    assert report.p50_ms == 200.0  # nearest-rank: ceil(0.5*4)=2 -> 200
    assert report.p95_ms == 400.0
    assert report.p99_ms == 400.0
    assert lt.report("run-1") is report

    # thresholds: one passes, one fails
    verdict = lt.check(
        "run-1", {"p95_ms": ("<", 500.0), "error_rate": ("<", 0.01)}, 2
    )
    assert verdict.passed is False
    by_name = {r.name: r for r in verdict.results}
    assert by_name["p95_ms"].passed is True
    assert by_name["error_rate"].passed is False
    assert verdict.digest.startswith("sha256:")

    # all-pass thresholds
    verdict2 = lt.check("run-1", {"avg_ms": ("<=", 250.0)}, 3)
    assert verdict2.passed is True

    # deterministic simulator: identical (scenario, seed) -> identical report
    # (fresh identical instances so run-ids match)
    fresh_a = LoadTester()
    fresh_a.define("smoke", [ScenarioStage(2, 3), (1, 4)], 0)
    fresh_b = LoadTester()
    fresh_b.define("smoke", [ScenarioStage(2, 3), (1, 4)], 0)
    sim_a = fresh_a.run("smoke", 4, seed=b"seed")
    sim_c = fresh_b.run("smoke", 4, seed=b"seed")
    assert sim_a.total_requests == sim_c.total_requests == 10
    assert sim_a.digest == sim_c.digest
    sim_d = fresh_b.run("smoke", 5, seed=b"other")
    assert sim_d.digest != sim_c.digest

    # fail-closed paths
    try:
        lt.define("smoke", [(1, 1)], 9)
    except DuplicateScenarioError:
        pass
    else:
        raise AssertionError("duplicate scenario accepted")
    try:
        lt.run("nope", 0)
    except UnknownScenarioError:
        pass
    else:
        raise AssertionError("unknown scenario accepted")
    try:
        lt.report("run-99")
    except UnknownRunError:
        pass
    else:
        raise AssertionError("unknown run accepted")
    try:
        lt.check("run-1", {"bogus": ("<", 1.0)}, 0)
    except LoadTesterError:
        pass
    else:
        raise AssertionError("unknown threshold metric accepted")
    try:
        lt.check("run-1", {"p95_ms": ("~", 1.0)}, 0)
    except LoadTesterError:
        pass
    else:
        raise AssertionError("unknown threshold op accepted")
    try:
        ScenarioStage(-1, 2)
    except LoadTesterError:
        pass
    else:
        raise AssertionError("negative duration accepted")
    big = LoadTester()
    big.define("huge", [ScenarioStage(10_000_000, 10_000_000)], 0)
    try:
        big.run("huge", 0)
    except TooManyIterationsError:
        pass
    else:
        raise AssertionError("iteration ceiling not enforced")

    # audit event shapes
    event = load_tester_audit_event(
        "run-completed", 7, {"run_id": "run-1", "digest": report.digest}
    )
    assert event["schema"] == "northstar.audit.ndjson/1"
    assert event["module"] == "load-tester.v1"
    try:
        load_tester_audit_event("bogus-kind", 0, {})
    except LoadTesterError:
        pass
    else:
        raise AssertionError("unknown audit kind accepted")

    # empty-plan run aggregates to zeros, never NaN
    empty = LoadTester()
    empty.define("idle", [(0, 5)], 0)
    zero = empty.run("idle", 0)
    assert zero.total_requests == 0
    assert zero.error_rate == 0.0
    assert zero.avg_ms == 0.0

    print("load-tester OK: define, run, aggregate, thresholds, fail-closed")


if __name__ == "__main__":
    main()
