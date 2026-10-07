"""Benchmarks as a deterministic single-host decision ledger.

Research note: a *benchmark* here is a governance task, not a stopwatch.
Real evaluation harnesses declare a benchmark task (what capability the
suite probes), book declared runs (what the host says happened), and
derive scores from the ledger. This module is the bookkeeping layer for
that loop: ``create()`` declares one benchmark task, ``run()`` books one
declared run over a pinned outcome vocabulary, and ``score()`` derives
an aggregate score posture from the ledger. It executes nothing, runs
no suite, measures no capability, and proves nothing about a system's
real performance or safety.

Distinct-layer rationale: ``benchmark_runner.py`` owns the *hyperfine-style
timing* ledger (host-claimed integer durations, exact median/p90/stddev
statistics, compare/regress against pinned baselines); and
``benchmark_retirement_probes.py`` owns retirement probing of benchmarks.
Per the additive sibling pattern, this module is the benchmark *task
governance* decision ledger none of them own: benchmark task creation,
declared run bookkeeping, derived score reports, and terminal retirement --
all booked as data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``benchmark.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``passed`` run means "the host declared a pass",
never that the system passed. A ``passed`` posture means the ledger's
derivation rule fired, never real-world quality. Scores are host-reported
ints in [0, 100], booked as data.

Version pin: benchmark.v1
Schema pin: northstar.benchmark.v1
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from fractions import Fraction

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version.
BENCHMARK_VERSION = "benchmark.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.benchmark.v1"

#: Pinned benchmark task-kind vocabulary (declared task domains).
TASK_KINDS = (
    "capability",
    "safety",
    "robustness",
    "alignment",
    "reasoning",
    "tool-use",
    "agentic",
    "evaluation",
)

#: Pinned run-outcome vocabulary (booked as data, never evidence).
RUN_OUTCOMES = (
    "passed",
    "failed",
    "inconclusive",
    "not-run",
)

#: Pinned score-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "unrun",
    "passed",
    "failed",
    "partial",
    "inconclusive",
)

#: Pinned retirement reasons (terminal off-ramp).
RETIRE_REASONS = (
    "manual",
    "superseded",
    "deprecated",
    "withdrawn",
)

#: Keys banned from audit details (raw benchmark material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "scenario",
    "transcript", "prompt", "response", "weights", "result",
    "dataset", "tasks", "items", "questions", "answers",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class BenchmarkError(Exception):
    """Base error for benchmark misuse."""


class SeqOrderError(BenchmarkError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(BenchmarkError):
    """Raised on a malformed benchmark or run id."""


class UnknownBenchmarkError(BenchmarkError):
    """Raised when a benchmark id has no booked rows (pure-read lookups)."""


class UnknownRecordError(BenchmarkError):
    """Raised when a run id is unknown."""


class DuplicateBenchmarkError(BenchmarkError):
    """Raised when a benchmark id is already registered (never recycled)."""


class RetiredBenchmarkError(BenchmarkError):
    """Raised when mutating a retired benchmark id (terminal, never recycled)."""


class BadKindError(BenchmarkError):
    """Raised on a task kind outside the pinned vocabulary."""


class BadOutcomeError(BenchmarkError):
    """Raised on a run outcome outside the pinned vocabulary."""


class BadScoreError(BenchmarkError):
    """Raised on a score outside int [0, 100] (bool refused)."""


class BadDigestError(BenchmarkError):
    """Raised on a malformed sha256: digest pin."""


class BadReasonError(BenchmarkError):
    """Raised on a retirement reason outside the pinned vocabulary."""


class AuditKindError(BenchmarkError):
    """Raised on an unknown audit kind or a banned audit key."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(body: dict) -> str:
    # The in-repo jcs_sha256_hex returns bare hex; pin it explicitly.
    return "sha256:" + jcs_sha256_hex(body)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadDigestError("digest must be a sha256: pin or ''")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


def _check_score(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("score must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadScoreError("score must be in [0, 100]")
    return value


def _mean_int(scores: tuple[int, ...]) -> int:
    """Exact integer mean (rounded half up); scores are ints, no floats."""
    n = len(scores)
    num, den = sum(scores), n
    q, r = divmod(num, den)
    return q + (1 if 2 * r >= den else 0)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BenchmarkRecord:
    """One declared benchmark task."""

    benchmark_id: str
    task_kind: str
    benchmark_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "benchmark_id": self.benchmark_id,
            "task_kind": self.task_kind,
            "benchmark_digest": self.benchmark_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RunRecord:
    """One declared benchmark run (minted run-N)."""

    run_id: str
    benchmark_id: str
    outcome: str
    score: int
    result_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "benchmark_id": self.benchmark_id,
            "outcome": self.outcome,
            "score": self.score,
            "result_digest": self.result_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RetireRecord:
    """One terminal benchmark retirement (ids never recycled)."""

    benchmark_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "benchmark_id": self.benchmark_id,
            "reason": self.reason,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class ScoreReport:
    """Derived benchmark score report (pure read)."""

    seq: int
    benchmark_id: str
    n_benchmarks: int
    n_runs: int
    mean_score: int
    outcome_tallies: tuple
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "benchmark_id": self.benchmark_id,
            "n_benchmarks": self.n_benchmarks,
            "n_runs": self.n_runs,
            "mean_score": self.mean_score,
            "outcome_tallies": [list(p) for p in self.outcome_tallies],
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "created",
    "run",
    "retired",
    "benchmark.rejected",
)


def benchmark_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw benchmark keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw benchmark key banned from audit: {key!r}")
    return {"kind": "benchmark." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class Benchmark:
    """Benchmark task governance ledger: create -> run -> score -> retire."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._benchmarks: dict[str, BenchmarkRecord] = {}
        self._benchmark_ids: list[str] = []
        self._runs: dict[str, RunRecord] = {}
        self._run_ids: list[str] = []
        self._runs_by_benchmark: dict[str, list[str]] = {}
        self._retired: dict[str, RetireRecord] = {}
        self._audit: list[dict] = []
        self._n_rejected = 0

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(benchmark_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("benchmark.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def create(self, benchmark_id: str, seq: int,
               task_kind: str = "capability",
               benchmark_digest: str = "") -> BenchmarkRecord:
        """Declare one benchmark task.

        The task is booked *as data*: a declared ``safety`` benchmark is
        a host claim about the suite's domain, never proof of coverage.
        Retired ids are never recycled.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(benchmark_id)
                if task_kind not in TASK_KINDS:
                    raise BadKindError(f"bad task kind: {task_kind!r}")
                _check_digest(benchmark_digest)
                if benchmark_id in self._retired:
                    raise RetiredBenchmarkError(
                        f"benchmark {benchmark_id!r} retired: ids never recycled")
                if benchmark_id in self._benchmarks:
                    raise DuplicateBenchmarkError(
                        f"benchmark {benchmark_id!r} already declared")
                body = {
                    "schema": SCHEMA_PIN,
                    "benchmark_id": benchmark_id,
                    "task_kind": task_kind,
                    "benchmark_digest": benchmark_digest,
                    "seq": seq,
                }
                rec = BenchmarkRecord(
                    benchmark_id=benchmark_id,
                    task_kind=task_kind,
                    benchmark_digest=benchmark_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._benchmarks[benchmark_id] = rec
                self._benchmark_ids.append(benchmark_id)
                self._runs_by_benchmark[benchmark_id] = []
                self._emit("created", {
                    "benchmark_id": benchmark_id,
                    "task_kind": task_kind,
                    "seq": seq,
                })
                return rec
            except BenchmarkError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def run(self, benchmark_id: str, seq: int,
            outcome: str = "passed",
            score: int = 0,
            result_digest: str = "") -> RunRecord:
        """Book one declared benchmark run (minted run-N).

        The outcome and score are booked *as data*: a ``passed`` outcome
        means the host declared a pass; ``score`` is a host-reported int
        in [0, 100]. Refused fail-closed on unknown or retired benchmarks.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(benchmark_id)
                if outcome not in RUN_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                _check_score(score)
                _check_digest(result_digest)
                if benchmark_id in self._retired:
                    raise RetiredBenchmarkError(
                        f"benchmark {benchmark_id!r} retired: no more runs")
                if benchmark_id not in self._benchmarks:
                    raise UnknownBenchmarkError(
                        f"benchmark {benchmark_id!r} not declared")
                run_id = f"run-{len(self._run_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "run_id": run_id,
                    "benchmark_id": benchmark_id,
                    "outcome": outcome,
                    "score": score,
                    "result_digest": result_digest,
                    "seq": seq,
                }
                rec = RunRecord(
                    run_id=run_id,
                    benchmark_id=benchmark_id,
                    outcome=outcome,
                    score=score,
                    result_digest=result_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._runs[run_id] = rec
                self._run_ids.append(run_id)
                self._runs_by_benchmark[benchmark_id].append(run_id)
                self._emit("run", {
                    "run_id": run_id,
                    "benchmark_id": benchmark_id,
                    "outcome": outcome,
                    "score": score,
                    "seq": seq,
                })
                return rec
            except BenchmarkError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def retire(self, benchmark_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminal benchmark retirement; ids are never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(benchmark_id)
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if benchmark_id in self._retired:
                    raise RetiredBenchmarkError(
                        f"benchmark {benchmark_id!r} already retired")
                if benchmark_id not in self._benchmarks:
                    raise UnknownBenchmarkError(
                        f"benchmark {benchmark_id!r} not declared")
                body = {
                    "schema": SCHEMA_PIN,
                    "benchmark_id": benchmark_id,
                    "reason": reason,
                    "seq": seq,
                }
                rec = RetireRecord(
                    benchmark_id=benchmark_id,
                    reason=reason,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._retired[benchmark_id] = rec
                self._emit("retired", {
                    "benchmark_id": benchmark_id,
                    "reason": reason,
                    "seq": seq,
                })
                return rec
            except BenchmarkError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def benchmark_record(self, benchmark_id: str, seq: int) -> BenchmarkRecord:
        with self._lock:
            self._view_seq(seq)
            _check_id(benchmark_id)
            try:
                return self._benchmarks[benchmark_id]
            except KeyError:
                raise UnknownBenchmarkError(
                    f"benchmark {benchmark_id!r} not declared")

    def run_record(self, run_id: str, seq: int) -> RunRecord:
        with self._lock:
            self._view_seq(seq)
            _check_id(run_id)
            try:
                return self._runs[run_id]
            except KeyError:
                raise UnknownRecordError(f"run {run_id!r} unknown")

    def benchmark_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._benchmark_ids)

    def runs_for(self, benchmark_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            _check_id(benchmark_id)
            try:
                return tuple(self._runs_by_benchmark[benchmark_id])
            except KeyError:
                raise UnknownBenchmarkError(
                    f"benchmark {benchmark_id!r} not declared")

    def retired_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._retired))

    def score(self, seq: int, benchmark_id: str = "") -> ScoreReport:
        """Derive the benchmark score report (pure read).

        Posture rules (ledger data, never measured truth):
        - ``unrun`` when no runs are booked
        - ``failed`` when any ``failed`` outcome stands
        - ``inconclusive`` when every run is ``inconclusive``
        - ``passed`` when every run ``passed``
        - ``partial`` otherwise (mixed declared outcomes)
        The mean score is the exact integer mean of booked host scores.
        """
        with self._lock:
            self._view_seq(seq)
            if benchmark_id:
                _check_id(benchmark_id)
                if benchmark_id not in self._benchmarks:
                    raise UnknownBenchmarkError(
                        f"benchmark {benchmark_id!r} not declared")
                run_ids = list(self._runs_by_benchmark[benchmark_id])
                n_benchmarks = 1
            else:
                run_ids = list(self._run_ids)
                n_benchmarks = len(self._benchmark_ids)
            runs = [self._runs[rid] for rid in run_ids]
            tallies = {o: 0 for o in RUN_OUTCOMES}
            for r in runs:
                tallies[r.outcome] += 1
            if not runs:
                posture = "unrun"
                mean_score = 0
            elif tallies["failed"] > 0:
                posture = "failed"
                mean_score = _mean_int(tuple(r.score for r in runs))
            elif tallies["inconclusive"] == len(runs):
                posture = "inconclusive"
                mean_score = _mean_int(tuple(r.score for r in runs))
            elif tallies["passed"] == len(runs):
                posture = "passed"
                mean_score = _mean_int(tuple(r.score for r in runs))
            else:
                posture = "partial"
                mean_score = _mean_int(tuple(r.score for r in runs))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "benchmark_id": benchmark_id,
                "n_benchmarks": n_benchmarks,
                "n_runs": len(runs),
                "mean_score": mean_score,
                "outcome_tallies": sorted(tallies.items()),
                "posture": posture,
            }
            return ScoreReport(
                seq=seq,
                benchmark_id=benchmark_id,
                n_benchmarks=n_benchmarks,
                n_runs=len(runs),
                mean_score=mean_score,
                outcome_tallies=tuple(sorted(tallies.items())),
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "benchmarks": len(self._benchmark_ids),
                "runs": len(self._run_ids),
                "retired": len(self._retired),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    b = Benchmark()
    rec = b.create("bench-1", 1, task_kind="safety")
    assert rec.verify()
    r1 = b.run("bench-1", 2, outcome="passed", score=90)
    assert r1.run_id == "run-1" and r1.verify()
    rep = b.score(3, "bench-1")
    assert rep.verify() and rep.posture == "passed" and rep.mean_score == 90
    b.retire("bench-1", 4)
    assert b.stats(5)["retired"] == 1
    print("benchmark OK: create, run, score, retire, pins, audit")


if __name__ == "__main__":
    main()
