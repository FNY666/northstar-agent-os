"""Hyperfine-style benchmark bookkeeping.

Research note: a *benchmark runner* records repeated wall-clock timings of
a command (hyperfine lineage: warmup runs, outlier trimming, summary
statistics) and answers two production questions -- "is A faster than B?"
(``compare()``) and "did the latest run regress against the pinned
baseline?" (``regress()``) -- all kept here:

* **Timing as integers** -- durations are int microseconds. Floats (and
  bools) are refused fail-closed at the boundary: no IEEE noise enters
  the statistics path, and digest pins bind exact integers.
* **Exact statistics** -- min / max / median / mean / p90 / population
  stddev are computed with exact integer arithmetic (``Fraction`` where a
  quotient is needed, ``math.isqrt`` for the stddev); nothing is rounded
  before it is pinned.
* **Host-reported truth** -- the module pins the durations the host
  *claims*; it cannot run commands, warm caches, or prove the timings
  were measured fairly (GIGO boundary, stated in the honest-scope note).
  Medians are the comparison statistic, not the single fastest run.
* **Baseline ledger** -- ``set_baseline()`` pins one run as the named
  reference; ``regress()`` refuses fail-closed when no baseline exists,
  and consumes its seq so a failed check leaves a ledger position.
* **Strict seqs** -- every record-producing call takes a caller-supplied
  strictly increasing int seq; the module never touches the wall clock.

Honest scope: this is *benchmark bookkeeping* over simulated results, not
a measurement harness. It computes exact statistics over host-supplied
durations, pins comparisons and regression verdicts, and refuses
malformed input fail-closed -- but ``bench()`` does not execute the
command, ``compare()`` proves "the reported medians differ by X%", never
"the code is faster", and ``regress()`` proves "the reported median moved
by X% against the pinned baseline", never that a deploy caused it.

Version pin: benchmark-runner.v1
Schema pin: northstar.benchmark-runner.v1
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
BENCHMARK_RUNNER_VERSION = "benchmark-runner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.benchmark-runner.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fewest runs accepted for a benchmark record (statistics need data).
MIN_RUNS = 3

#: Largest single duration accepted: 24h in microseconds (guardrail).
MAX_DURATION_US = 24 * 3600 * 1_000_000

#: Largest accepted margin/threshold percentage (a wider band is a lie).
MAX_PCT = 50


class BenchmarkError(Exception):
    """Base error for benchmark runner misuse or constraint violations."""


class ValidationError(BenchmarkError):
    """A field failed fail-closed validation."""


class SeqOrderError(BenchmarkError):
    """A caller seq did not strictly increase."""


class UnknownBenchmarkError(BenchmarkError):
    """A benchmark name was never registered."""


class DuplicateBenchmarkError(BenchmarkError):
    """A benchmark name is already registered and is never recycled."""


class NoRunError(BenchmarkError):
    """The named benchmark has no recorded run yet."""


class NoBaselineError(BenchmarkError):
    """The named benchmark has no pinned baseline yet."""


class InsufficientRunsError(BenchmarkError):
    """Fewer durations were supplied than the benchmark's run count."""


class BadDurationError(BenchmarkError):
    """A claimed duration was non-int, non-positive, or absurd."""


class BadThresholdError(BenchmarkError):
    """A margin/threshold percentage was out of range."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("benchmark name must be a non-empty str")
    return name.strip()


def _check_pct(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{what} must be an int, not bool")
    if value < 0 or value > MAX_PCT:
        raise BadThresholdError(f"{what} must be within [0, {MAX_PCT}]")
    return value


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _check_durations(durations: Any, expected_runs: int) -> Tuple[int, ...]:
    if not isinstance(durations, (list, tuple)) or isinstance(durations, bool):
        raise BadDurationError("durations must be a list/tuple of int microseconds")
    out = []
    for d in durations:
        if isinstance(d, bool) or not isinstance(d, int):
            raise BadDurationError("each duration must be an int, not bool")
        if d < 1 or d > MAX_DURATION_US:
            raise BadDurationError("each duration must be within [1, MAX_DURATION_US]")
        out.append(d)
    if len(out) < max(MIN_RUNS, expected_runs):
        raise InsufficientRunsError(
            f"need at least {max(MIN_RUNS, expected_runs)} durations, got {len(out)}"
        )
    return tuple(out)


def _round_half_up_frac(fr: Fraction) -> int:
    n, d = fr.numerator, fr.denominator
    q, r = divmod(n, d)
    if 2 * r >= d:
        q += 1
    return q


def _median_us(sorted_us: Tuple[int, ...]) -> int:
    n = len(sorted_us)
    mid = n // 2
    if n % 2 == 1:
        return sorted_us[mid]
    return _round_half_up_frac(Fraction(sorted_us[mid - 1] + sorted_us[mid], 2))


def _stddev_us(values: Tuple[int, ...], mean_frac: Fraction) -> int:
    """Population stddev in us, rounded to int via isqrt (no floats)."""
    n = len(values)
    # exact variance numerator/denominator as integers
    num = sum((v * mean_frac.denominator - mean_frac.numerator) ** 2 for v in values)
    den = n * mean_frac.denominator * mean_frac.denominator
    # isqrt(num / den) rounded to nearest int
    q = math.isqrt(num * 1_000_000 // den)  # milli-us precision
    q, r = divmod(q, 1000)
    return q + (1 if 2 * r >= 1000 else 0)


@dataclass(frozen=True)
class BenchmarkSpec:
    """A registered benchmark: pinned name, expected run count, command."""

    name: str
    description: str
    cmdline: str
    runs: int
    warmup_runs: int
    spec_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


@dataclass(frozen=True)
class BenchmarkRun:
    """One benchmark recording: exact stats over pinned host durations."""

    run_id: str
    name: str
    durations_us: Tuple[int, ...]
    count: int
    min_us: int
    max_us: int
    median_us: int
    mean_us: int
    p90_us: int
    stddev_us: int
    note: str
    run_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


@dataclass(frozen=True)
class BaselineRecord:
    """A pinned baseline run for a named benchmark."""

    name: str
    run_id: str
    median_us: int
    baseline_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


@dataclass(frozen=True)
class ComparisonReport:
    """compare(): exact median ratio and a margin-banded verdict."""

    report_id: str
    name_a: str
    name_b: str
    run_a: str
    run_b: str
    median_a_us: int
    median_b_us: int
    ratio_num: int
    ratio_den: int
    margin_pct: int
    verdict: str  # "a-faster" | "b-faster" | "indistinguishable"
    report_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


@dataclass(frozen=True)
class RegressionReport:
    """regress(): exact median delta against the pinned baseline."""

    report_id: str
    name: str
    run_id: str
    baseline_run_id: str
    baseline_median_us: int
    current_median_us: int
    delta_pct_num: int
    delta_pct_den: int
    threshold_pct: int
    verdict: str  # "regressed" | "improved" | "stable"
    report_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


@dataclass(frozen=True)
class LeaderboardEntry:
    """One ranked benchmark row: latest run plus its board position."""

    rank: int
    name: str
    run_id: str
    median_us: int
    mean_us: int
    min_us: int
    max_us: int
    p90_us: int
    entry_pin: str
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


@dataclass(frozen=True)
class LeaderboardReport:
    """leaderboard(): benchmarks ranked fastest-first by a pinned metric."""

    metric: str  # "median_us" | "mean_us" | "min_us" | "max_us" | "p90_us"
    entries: Tuple[LeaderboardEntry, ...]
    report_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = BENCHMARK_RUNNER_VERSION


#: Metrics a leaderboard may rank by (exact field names on BenchmarkRun).
LEADERBOARD_METRICS = ("median_us", "mean_us", "min_us", "max_us", "p90_us")


class BenchmarkRunner:
    """Hyperfine-shaped benchmark ledger: record, compare, regress.

    All statistics are computed over host-claimed integer microsecond
    durations with exact arithmetic; records are frozen and digest-pinned.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._specs: Dict[str, BenchmarkSpec] = {}
        self._runs: Dict[str, BenchmarkRun] = {}
        self._by_name: Dict[str, List[str]] = {}
        self._latest: Dict[str, str] = {}
        self._baselines: Dict[str, BaselineRecord] = {}
        self._audit: List[Dict[str, Any]] = []
        self._run_counter = 0
        self._report_counter = 0

    # -- seq discipline ------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq {seq} did not exceed last {self._last_seq}")
        self._last_seq = seq  # failed mutations consume their seq (fail-closed)
        return seq

    def _emit(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        self._audit.append(benchmark_runner_audit_event(kind, seq, detail))

    # -- registration --------------------------------------------------

    def register(
        self,
        name: Any,
        seq: Any,
        *,
        description: str = "",
        cmdline: str = "",
        runs: int = 10,
        warmup_runs: int = 3,
    ) -> BenchmarkSpec:
        name = _check_name(name)
        if isinstance(runs, bool) or not isinstance(runs, int) or runs < MIN_RUNS:
            raise ValidationError(f"runs must be an int >= {MIN_RUNS}")
        if isinstance(warmup_runs, bool) or not isinstance(warmup_runs, int) or warmup_runs < 0:
            raise ValidationError("warmup_runs must be a non-negative int")
        if not isinstance(description, str) or not isinstance(cmdline, str):
            raise ValidationError("description/cmdline must be str")
        with self._lock:
            seq = self._claim_seq(seq)
            if name in self._specs:
                raise DuplicateBenchmarkError(f"benchmark {name!r} already registered")
            body = {"name": name, "description": description, "cmdline": cmdline,
                    "runs": runs, "warmup_runs": warmup_runs}
            spec = BenchmarkSpec(
                name=name, description=description, cmdline=cmdline,
                runs=runs, warmup_runs=warmup_runs,
                spec_pin=_pin(body), seq=seq,
            )
            self._specs[name] = spec
            self._by_name[name] = []
            self._emit("benchmark-registered", seq, {"name": name, "pin": spec.spec_pin})
            return spec

    def set_baseline(self, name: Any, seq: Any) -> BaselineRecord:
        name = _check_name(name)
        with self._lock:
            seq = self._claim_seq(seq)
            run_id = self._latest.get(name)
            if run_id is None:
                raise NoRunError(f"benchmark {name!r} has no recorded run")
            run = self._runs[run_id]
            body = {"name": name, "run_id": run_id, "median_us": run.median_us}
            rec = BaselineRecord(
                name=name, run_id=run_id, median_us=run.median_us,
                baseline_pin=_pin(body), seq=seq,
            )
            self._baselines[name] = rec
            self._emit("baseline-pinned", seq, {"name": name, "run": run_id})
            return rec

    # -- recording -----------------------------------------------------

    def bench(
        self,
        name: Any,
        seq: Any,
        durations_us: Any,
        *,
        note: str = "",
    ) -> BenchmarkRun:
        name = _check_name(name)
        if not isinstance(note, str):
            raise ValidationError("note must be str")
        with self._lock:
            seq = self._claim_seq(seq)
            spec = self._specs.get(name)
            if spec is None:
                raise UnknownBenchmarkError(f"benchmark {name!r} not registered")
            values = _check_durations(durations_us, spec.runs)
            ordered = tuple(sorted(values))
            n = len(ordered)
            mean_frac = Fraction(sum(ordered), n)
            median = _median_us(ordered)
            rank = (9 * n + 9) // 10  # nearest-rank p90: ceil(0.9*n)
            self._run_counter += 1
            run_id = f"run-{self._run_counter}"
            body = {"run_id": run_id, "name": name, "durations_us": list(values),
                    "note": note}
            run = BenchmarkRun(
                run_id=run_id, name=name, durations_us=values, count=n,
                min_us=ordered[0], max_us=ordered[-1], median_us=median,
                mean_us=_round_half_up_frac(mean_frac),
                p90_us=ordered[rank - 1],
                stddev_us=_stddev_us(ordered, mean_frac),
                note=note, run_pin=_pin(body), seq=seq,
            )
            self._runs[run_id] = run
            self._by_name[name].append(run_id)
            self._latest[name] = run_id
            self._emit("benchmark-run", seq,
                        {"name": name, "run": run_id, "pin": run.run_pin})
            return run

    # -- analysis ------------------------------------------------------

    def compare(
        self,
        name_a: Any,
        name_b: Any,
        seq: Any,
        *,
        margin_pct: int = 2,
    ) -> ComparisonReport:
        name_a = _check_name(name_a)
        name_b = _check_name(name_b)
        margin = _check_pct(margin_pct, "margin_pct")
        with self._lock:
            seq = self._claim_seq(seq)
            run_a_id = self._latest.get(name_a)
            run_b_id = self._latest.get(name_b)
            if run_a_id is None:
                raise NoRunError(f"benchmark {name_a!r} has no recorded run")
            if run_b_id is None:
                raise NoRunError(f"benchmark {name_b!r} has no recorded run")
            run_a = self._runs[run_a_id]
            run_b = self._runs[run_b_id]
            med_a, med_b = run_a.median_us, run_b.median_us
            ratio = Fraction(med_a, med_b)
            lo, hi = 100 - margin, 100 + margin
            if med_a * 100 < med_b * lo:
                verdict = "a-faster"
            elif med_a * 100 > med_b * hi:
                verdict = "b-faster"
            else:
                verdict = "indistinguishable"
            self._report_counter += 1
            report_id = f"cmp-{self._report_counter}"
            body = {"report_id": report_id, "name_a": name_a, "name_b": name_b,
                    "run_a": run_a_id, "run_b": run_b_id,
                    "ratio_num": ratio.numerator, "ratio_den": ratio.denominator,
                    "margin_pct": margin, "verdict": verdict}
            report = ComparisonReport(
                report_id=report_id, name_a=name_a, name_b=name_b,
                run_a=run_a_id, run_b=run_b_id,
                median_a_us=med_a, median_b_us=med_b,
                ratio_num=ratio.numerator, ratio_den=ratio.denominator,
                margin_pct=margin, verdict=verdict,
                report_pin=_pin(body), seq=seq,
            )
            self._emit("compared", seq,
                        {"report": report_id, "a": name_a, "b": name_b,
                         "verdict": verdict})
            return report

    def regress(
        self,
        name: Any,
        seq: Any,
        *,
        threshold_pct: int = 5,
    ) -> RegressionReport:
        name = _check_name(name)
        threshold = _check_pct(threshold_pct, "threshold_pct")
        with self._lock:
            seq = self._claim_seq(seq)
            baseline = self._baselines.get(name)
            if baseline is None:
                raise NoBaselineError(f"benchmark {name!r} has no pinned baseline")
            run_id = self._latest.get(name)
            if run_id is None:  # pragma: no cover - baseline implies a run
                raise NoRunError(f"benchmark {name!r} has no recorded run")
            run = self._runs[run_id]
            base_med, cur_med = baseline.median_us, run.median_us
            delta = Fraction(cur_med - base_med, base_med) * 100
            if (cur_med - base_med) * 100 >= threshold * base_med:
                verdict = "regressed"
            elif (base_med - cur_med) * 100 >= threshold * base_med:
                verdict = "improved"
            else:
                verdict = "stable"
            self._report_counter += 1
            report_id = f"reg-{self._report_counter}"
            body = {"report_id": report_id, "name": name, "run_id": run_id,
                    "baseline_run_id": baseline.run_id,
                    "delta_pct_num": delta.numerator, "delta_pct_den": delta.denominator,
                    "threshold_pct": threshold, "verdict": verdict}
            report = RegressionReport(
                report_id=report_id, name=name, run_id=run_id,
                baseline_run_id=baseline.run_id,
                baseline_median_us=base_med, current_median_us=cur_med,
                delta_pct_num=delta.numerator, delta_pct_den=delta.denominator,
                threshold_pct=threshold, verdict=verdict,
                report_pin=_pin(body), seq=seq,
            )
            self._emit("regression-checked", seq,
                        {"report": report_id, "name": name, "verdict": verdict})
            return report

    # -- pure views ----------------------------------------------------

    def spec(self, name: Any) -> BenchmarkSpec:
        name = _check_name(name)
        try:
            return self._specs[name]
        except KeyError:
            raise UnknownBenchmarkError(f"benchmark {name!r} not registered")

    def task(self, name: Any) -> BenchmarkSpec:
        """Spec alias: return the registered benchmark task for ``name``.

        Pure read view -- same shape, errors, and pins as ``spec()``.
        """
        return self.spec(name)

    def run(self, run_id: Any) -> BenchmarkRun:
        if not isinstance(run_id, str):
            raise ValidationError("run_id must be str")
        try:
            return self._runs[run_id]
        except KeyError:
            raise NoRunError(f"run {run_id!r} unknown")

    def runs(self, name: Any) -> Tuple[str, ...]:
        name = _check_name(name)
        if name not in self._specs:
            raise UnknownBenchmarkError(f"benchmark {name!r} not registered")
        return tuple(self._by_name[name])

    def latest(self, name: Any) -> BenchmarkRun:
        name = _check_name(name)
        run_id = self._latest.get(name)
        if run_id is None:
            raise NoRunError(f"benchmark {name!r} has no recorded run")
        return self._runs[run_id]

    def leaderboard(
        self, seq: Any, metric: str = "median_us"
    ) -> LeaderboardReport:
        """Rank registered benchmarks fastest-first by a pinned metric.

        Pure read view: validates the seq shape, consumes nothing, writes no
        audit row. Only benchmarks with a recorded latest run appear; a
        benchmark with no run is skipped as data, never raised. An empty
        board (no runs recorded at all) returns ``entries == ()`` as data.
        Sort is by (metric value, name): lower is faster, ties break by
        name, so the board is deterministic across instances.
        """
        _check_seq(seq)
        if not isinstance(metric, str) or metric not in LEADERBOARD_METRICS:
            raise ValidationError(
                f"metric must be one of {LEADERBOARD_METRICS}"
            )
        with self._lock:
            rows = []
            for name in self._specs:
                run_id = self._latest.get(name)
                if run_id is None:
                    continue
                run = self._runs[run_id]
                rows.append((getattr(run, metric), name, run))
            rows.sort(key=lambda r: (r[0], r[1]))
            entries: List[LeaderboardEntry] = []
            for rank, (_value, name, run) in enumerate(rows, start=1):
                body = {
                    "rank": rank, "name": name, "run_id": run.run_id,
                    "metric": metric, "value_us": getattr(run, metric),
                }
                entries.append(
                    LeaderboardEntry(
                        rank=rank, name=name, run_id=run.run_id,
                        median_us=run.median_us, mean_us=run.mean_us,
                        min_us=run.min_us, max_us=run.max_us,
                        p90_us=run.p90_us, entry_pin=_pin(body),
                    )
                )
            body = {
                "metric": metric,
                "entries": [e.entry_pin for e in entries],
            }
            return LeaderboardReport(
                metric=metric,
                entries=tuple(entries),
                report_pin=_pin(body),
                seq=seq,
            )

    def baseline(self, name: Any) -> BaselineRecord:
        name = _check_name(name)
        try:
            return self._baselines[name]
        except KeyError:
            raise NoBaselineError(f"benchmark {name!r} has no pinned baseline")

    def spec_names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._specs))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit)


def benchmark_runner_audit_event(
    kind: str, seq: int, detail: Mapping[str, Any]
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for benchmark runner events."""
    allowed = {
        "benchmark-registered", "baseline-pinned", "benchmark-run",
        "compared", "regression-checked", "rejected",
    }
    if kind not in allowed:
        raise ValidationError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {"kind": kind, "seq": seq, "schema": AUDIT_SCHEMA,
            "module": "benchmark_runner", "detail": dict(detail)}


def main() -> None:
    r = BenchmarkRunner()
    r.register("hash", 1, cmdline="sha256sum bigfile", runs=5, warmup_runs=2)
    run = r.bench("hash", 2, [100, 200, 300, 400, 500], note="smoke")
    assert (run.min_us, run.max_us, run.median_us, run.mean_us) == (100, 500, 300, 300)
    assert run.p90_us == 500
    r.set_baseline("hash", 3)
    r.register("sort", 4, cmdline="sort bigfile", runs=5)
    r.bench("sort", 5, [600, 610, 620, 630, 640])
    cmp_ = r.compare("hash", "sort", 6)
    assert cmp_.verdict == "a-faster"
    r.bench("hash", 7, [305, 308, 310, 312, 315])
    reg = r.regress("hash", 8)
    assert reg.verdict == "stable"
    r.bench("hash", 9, [700, 710, 720, 730, 740])
    reg2 = r.regress("hash", 10)
    assert reg2.verdict == "regressed"
    print("benchmark-runner OK: register, bench, baseline, compare, regress")


if __name__ == "__main__":
    main()
