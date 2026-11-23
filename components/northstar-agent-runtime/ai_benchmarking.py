"""AI benchmarking: AI-benchmarking decision ledger, Simulated.

Research note: AI benchmarks (capability suites, safety evaluations,
alignment probes, robustness batteries, fairness slices, efficiency
tests) never *prove* a model's real-world behavior - benchmarks leak,
models overfit to the suite, harness configurations drift, and every
score is a claim made by the host under a declared benchmark
configuration. What matters here is the *decision ledger*: which
systems were run through which declared benchmark suites, what
outcomes and declared scores were booked with what suite digest
pins, and how each booked record was itself verified - defensible
bookkeeping, never proof that a system is capable, safe, or aligned.

This module owns the benchmark -> verify -> evaluate lifecycle:

* **benchmark()** - book one declared benchmark run for a system
  (minted ``bmk-N`` ids; pinned 8-term benchmark vocabulary and
  pinned 5-term outcome vocabulary). The first benchmark registers
  its system. Declared scores (host-reported ints 0-100) are booked
  **as data**, never proof. Raw test items, gold answers, model
  weights, responses, and harness internals never enter records -
  digest pins only.
* **verify()** - pure read: re-derive one benchmark record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data (tamper
  reported, never raised). Seq shape-validated only, never
  consumed, no audit row.
* **evaluate()** - pure read: per-system benchmark tallies, a
  declared-score aggregate (as data), and a ledger-rule posture -
  all as data, never proof.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs sibling ledgers: ``ai_evaluation.py``
style modules book *general* assessment outcomes; this module is
the *benchmark-suite-run* ledger none of them own: system ->
declared suite -> declared benchmark kind -> declared outcome and
score -> ledger-rule posture.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-benchmarking.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no benchmarks, scores nothing,
executes no harness, and proves nothing about real capabilities,
safety, or alignment. A booked ``pass`` outcome means "the host
declared it", never "the system passed". Declared scores are data
for aggregation, never measurements of truth. Test items, gold
answers, weights, responses, and harness internals never enter
records or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
AI_BENCHMARKING_VERSION = "ai-benchmarking.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-benchmarking.v1"

#: Pinned benchmark-kind vocabulary (booked as data, never proof).
BENCHMARK_KINDS = (
    "capability",
    "safety",
    "alignment",
    "robustness",
    "fairness",
    "efficiency",
    "security",
    "governance",
)

#: Pinned benchmark-outcome vocabulary (booked as data, never proof).
OUTCOMES = (
    "pass",
    "fail",
    "partial",
    "inconclusive",
    "not-evaluated",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "benchmarked",
    "retired",
    "rejected",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "trajectory",
        "trajectories",
        "action",
        "actions",
        "state",
        "observation",
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "prompt",
        "response",
        "content",
        "text",
        "detail",
        "details",
        "description",
        "report",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
        "answers",
        "ground_truth",
        "labels",
        "test_items",
        "questions",
        "solutions",
        "golden",
        "dataset",
        "outputs",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIBenchmarkingError(Exception):
    """Base error for AI-benchmarking ledger misuse."""


class BadIdError(AIBenchmarkingError):
    """Malformed system, suite, or benchmark id."""


class RetiredSystemError(AIBenchmarkingError):
    """System id already retired; never recycled."""


class UnknownSystemError(AIBenchmarkingError):
    """System not registered."""


class BadBenchmarkKindError(AIBenchmarkingError):
    """Unknown benchmark kind."""


class BadDigestError(AIBenchmarkingError):
    """Malformed sha256: digest pin."""


class BadOutcomeError(AIBenchmarkingError):
    """Unknown benchmark outcome."""


class BadScoreError(AIBenchmarkingError):
    """Score is not a declared int in [0, 100]."""


class UnknownBenchmarkError(AIBenchmarkingError):
    """Benchmark id not booked."""


class BadReasonError(AIBenchmarkingError):
    """Unknown retirement reason."""


class SeqOrderError(AIBenchmarkingError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIBenchmarkingError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_score(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("score must be an int, not bool")
    if value < 0 or value > 100:
        raise BadScoreError("score must be in [0, 100]")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkRecord:
    benchmark_id: str
    system_id: str
    suite_id: str
    benchmark_kind: str
    outcome: str
    score: int
    suite_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "benchmark_id": self.benchmark_id,
            "system_id": self.system_id,
            "suite_id": self.suite_id,
            "benchmark_kind": self.benchmark_kind,
            "outcome": self.outcome,
            "score": self.score,
            "suite_digest": self.suite_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "benchmark_id": self.benchmark_id,
                "system_id": self.system_id,
                "suite_id": self.suite_id,
                "benchmark_kind": self.benchmark_kind,
                "outcome": self.outcome,
                "score": self.score,
                "suite_digest": self.suite_digest,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    record_kind: str
    verdict: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "verdict": self.verdict,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "record_id": self.record_id,
                "record_kind": self.record_kind,
                "verdict": self.verdict,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class BenchmarkEvaluation:
    system_id: str
    posture: str
    n_benchmarks: int
    n_pass: int
    n_fail: int
    n_partial: int
    n_inconclusive: int
    n_not_evaluated: int
    avg_score: float
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "posture": self.posture,
            "n_benchmarks": self.n_benchmarks,
            "n_pass": self.n_pass,
            "n_fail": self.n_fail,
            "n_partial": self.n_partial,
            "n_inconclusive": self.n_inconclusive,
            "n_not_evaluated": self.n_not_evaluated,
            "avg_score": self.avg_score,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "posture": self.posture,
                "n_benchmarks": self.n_benchmarks,
                "n_pass": self.n_pass,
                "n_fail": self.n_fail,
                "n_partial": self.n_partial,
                "n_inconclusive": self.n_inconclusive,
                "n_not_evaluated": self.n_not_evaluated,
                "avg_score": self.avg_score,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_benchmarking_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the AI-benchmarking ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIBenchmarking:
    """AI-benchmarking decision ledger, Simulated.

    ``benchmark()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``verify()``, ``evaluate()``, and the other views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._benchmarks: Dict[str, BenchmarkRecord] = {}
        self._benchmarks_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._bmk_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: AIBenchmarkingError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_benchmarking_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system already retired: {system_id!r}")

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations --------------------------------------------------------

    def benchmark(
        self,
        system_id: Any,
        suite_id: Any,
        seq: Any,
        benchmark_kind: Any = "capability",
        outcome: Any = "not-evaluated",
        score: Any = 0,
        suite_digest: Any = "",
    ) -> BenchmarkRecord:
        """Book one declared benchmark run (minted ``bmk-N``).

        The first benchmark registers its system. The declared
        ``score`` (host-reported int 0-100) is booked **as data**,
        never proof of real performance. Raw test items, gold
        answers, weights, responses, and harness internals travel as
        a digest pin only; they never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                suite = _require_id(suite_id, "suite_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(benchmark_kind, str) or benchmark_kind not in BENCHMARK_KINDS:
                    raise BadBenchmarkKindError(
                        f"benchmark_kind must be one of {sorted(BENCHMARK_KINDS)}"
                    )
                if not isinstance(outcome, str) or outcome not in OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(OUTCOMES)}"
                    )
                score_v = _require_score(score)
                pin = _require_digest(suite_digest, "suite_digest")
                self._bmk_counter += 1
                bid = f"bmk-{self._bmk_counter}"
                rec = BenchmarkRecord(
                    benchmark_id=bid,
                    system_id=sid,
                    suite_id=suite,
                    benchmark_kind=benchmark_kind,
                    outcome=outcome,
                    score=score_v,
                    suite_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "benchmark_id": bid,
                            "system_id": sid,
                            "suite_id": suite,
                            "benchmark_kind": benchmark_kind,
                            "outcome": outcome,
                            "score": score_v,
                            "suite_digest": pin,
                        }
                    ),
                )
                self._benchmarks[bid] = rec
                self._systems.setdefault(sid, []).append(bid)
                self._benchmarks_by_system.setdefault(sid, []).append(bid)
                self._audit.append(
                    ai_benchmarking_audit_event(
                        "benchmarked",
                        seq_v,
                        benchmark_id=bid,
                        system_id=sid,
                        suite_id=suite,
                        benchmark_kind=benchmark_kind,
                        outcome=outcome,
                        score=score_v,
                    )
                )
                return rec
            except AIBenchmarkingError as exc:
                self._burn(seq_v, "benchmark", exc)
                raise

    def retire(
        self,
        system_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system already retired: {sid!r}")
                self._require_known_system(sid)
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    system_id=sid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "system_id": sid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[sid] = rec
                self._audit.append(
                    ai_benchmarking_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIBenchmarkingError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def verify(self, record_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one benchmark record's digest pin (pure read).

        The verdict ``verified`` / ``tampered`` is booked as data -
        tamper is reported, never raised. The caller seq is
        shape-validated only: it is never consumed and no audit row
        is appended.
        """
        with self._lock:
            self._check_seq(seq)
            rid = _require_id(record_id, "record_id")
            rec = self._benchmarks.get(rid)
            if rec is None:
                raise UnknownBenchmarkError(f"unknown benchmark: {rid!r}")
            verdict = "verified" if rec.verify() else "tampered"
            return VerificationReport(
                record_id=rid,
                record_kind="benchmark",
                verdict=verdict,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "record_id": rid,
                        "record_kind": "benchmark",
                        "verdict": verdict,
                    }
                ),
            )

    def benchmark_record(self, benchmark_id: Any, seq: Any) -> BenchmarkRecord:
        """Return one benchmark record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            bid = _require_id(benchmark_id, "benchmark_id")
            if bid not in self._benchmarks:
                raise UnknownBenchmarkError(f"unknown benchmark: {bid!r}")
            return self._benchmarks[bid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def benchmark_ids(self, seq: Any) -> Tuple[str, ...]:
        """All benchmark ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"bmk-{i}" for i in range(1, self._bmk_counter + 1))

    def benchmarks_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Benchmark ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._benchmarks_by_system[sid])

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def evaluate(self, system_id: Any, seq: Any) -> BenchmarkEvaluation:
        """Per-system benchmark tallies and posture (pure read).

        ``posture`` is derived by the ledger rule as data:
        ``unevaluated`` (no benchmarks) -> ``failing`` (any fail,
        outranks) -> ``contested`` (any inconclusive) -> ``partial``
        (any partial) -> ``passing`` (all pass). ``avg_score``
        aggregates *declared* scores only - as data, never truth.
        ``integrity_ok`` is ledger truth derived from digest pins.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            bid_ids = self._benchmarks_by_system[sid]
            n_pass = n_fail = n_partial = n_inconclusive = n_not_evaluated = 0
            total_score = 0
            for bid in bid_ids:
                rec = self._benchmarks[bid]
                if rec.outcome == "pass":
                    n_pass += 1
                elif rec.outcome == "fail":
                    n_fail += 1
                elif rec.outcome == "partial":
                    n_partial += 1
                elif rec.outcome == "inconclusive":
                    n_inconclusive += 1
                else:
                    n_not_evaluated += 1
                total_score += rec.score
            if not bid_ids:
                posture = "unevaluated"
            elif n_fail > 0:
                posture = "failing"
            elif n_inconclusive > 0:
                posture = "contested"
            elif n_partial > 0:
                posture = "partial"
            elif n_not_evaluated > 0:
                posture = "partial"
            else:
                posture = "passing"
            avg_score = total_score / len(bid_ids) if bid_ids else 0.0
            integrity_ok = all(self._benchmarks[bid].verify() for bid in bid_ids)
            return BenchmarkEvaluation(
                system_id=sid,
                posture=posture,
                n_benchmarks=len(bid_ids),
                n_pass=n_pass,
                n_fail=n_fail,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                n_not_evaluated=n_not_evaluated,
                avg_score=avg_score,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "posture": posture,
                        "n_benchmarks": len(bid_ids),
                        "n_pass": n_pass,
                        "n_fail": n_fail,
                        "n_partial": n_partial,
                        "n_inconclusive": n_inconclusive,
                        "n_not_evaluated": n_not_evaluated,
                        "avg_score": avg_score,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "systems": len(self._systems),
                "benchmarks": len(self._benchmarks),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    b = AIBenchmarking()
    pin = "sha256:" + "ab" * 32
    rec = b.benchmark(
        "sys-1", "suite-1", 1, benchmark_kind="safety",
        outcome="pass", score=92, suite_digest=pin,
    )
    assert rec.benchmark_id == "bmk-1"
    rep = b.verify("bmk-1", 2)
    assert rep.verdict == "verified"
    ev = b.evaluate("sys-1", 3)
    assert ev.verify()
    assert ev.posture == "passing"
    assert ev.integrity_ok is True
    assert ev.n_pass == 1
    assert ev.avg_score == 92.0
    b.retire("sys-1", 4, reason="decommissioned")
    assert b.stats(5) == {
        "systems": 1,
        "benchmarks": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-benchmarking OK: benchmark, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
