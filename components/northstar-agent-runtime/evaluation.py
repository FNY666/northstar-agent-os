"""Evaluation: AI capability/safety evaluation governance ledger, Simulated.

Research note: agent evaluations ("evals") are the discipline that turns a
model or agent build into a *claim* - a protocol is designed (which task
domains, which methodology), runs are executed against it, and an analysis
is derived (pass, marginal, fail). The dangerous half of any such programme
is the *material*: the held-out eval items, questions, reference answers,
and model transcripts must never be bundled with the bookkeeping record
that tracks that a protocol was designed, that runs were declared, and
what the host reported as scores.

This module is that bookkeeping layer, deliberately distinct from its
siblings ``evaluation_harness.py`` (harness execution mechanics),
``benchmark_runner.py`` (benchmark suite execution), ``capability_eval.py`` /
``safety_eval.py`` / ``alignment_eval.py`` / ``fairness_eval.py`` /
``sleeper_eval.py`` (domain-specific eval mechanics), ``evaluator_access.py``
(evaluator access grants), and ``benchmark_retirement_probes.py``
(retirement probes): this module runs no model, executes no benchmark,
grades no transcript, and leaks no eval content. It books:

* **design()** - declare one eval protocol over the pinned task-domain and
  methodology vocabulary; protocol details travel as ``sha256:`` digest pins
  only - raw eval items, questions, and answers never enter a record.
* **run()** - book one declared run against a live design, minted ``run-N``
  ids; the aggregate score is host-reported (int, normalized to a 0..100
  scale) and booked **as data** - never proof a run actually executed or
  that the score was measured honestly.
* **analyze()** - pure-read derived verdict (``unevaluated`` / ``pass`` /
  ``marginal`` / ``fail``) by ledger rule, digest-pinned with ``verify()``;
  the verdict is derived data, never proof of real capability.
* **retire()** - terminal bookkeeping for superseded / completed protocols;
  ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``evaluation.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked design is a host-declared protocol, never proof an
evaluation was well designed; a booked run means the host said so, never
proof a model was actually evaluated; a derived "pass" verdict is ledger
arithmetic, never evidence the system is capable or safe.
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
EVALUATION_VERSION = "evaluation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.evaluation.v1"

#: Pinned eval task-domain vocabulary (what capability area is probed).
TASK_DOMAINS = (
    "reasoning",
    "coding",
    "tool-use",
    "safety",
    "alignment",
    "deception",
    "multimodal",
    "long-context",
)

#: Pinned evaluation-methodology vocabulary (how the eval is run).
METHODOLOGIES = (
    "held-out-suite",
    "human-grading",
    "model-grading",
    "behavioral-probe",
    "red-team-adversarial",
    "self-report",
)

#: Pinned run-kind vocabulary (declared run type).
RUN_KINDS = (
    "baseline",
    "elicitation",
    "ablated",
    "replicated",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "suite-superseded",
    "protocol-complete",
    "invalidated",
)

#: Ledger-rule verdict vocabulary derived by analyze() (as data).
VERDICTS = (
    "unevaluated",
    "pass",
    "marginal",
    "fail",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "designed",
    "run_recorded",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``run_kind``, ``score``, ``verdict``) are pinned
#: vocabulary / host-reported ints and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "item",
        "items",
        "question",
        "questions",
        "answer",
        "answers",
        "transcript",
        "prompt",
        "response",
        "weights",
        "solution",
        "reference",
        "grader",
        "grading",
        "raw",
        "content",
        "text",
        "data",
    }
)

#: Normalized-score thresholds used by the ledger-rule verdict (0..100).
PASS_MARK = 70
FAIL_MARK = 50


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EvaluationError(Exception):
    """Base error for evaluation ledger misuse."""


class BadIdError(EvaluationError):
    """Malformed design/run id."""


class DuplicateDesignError(EvaluationError):
    """A design id was declared twice."""


class UnknownDesignError(EvaluationError):
    """Reference to a design id that was never declared."""


class UnknownRunError(EvaluationError):
    """Reference to a run id that was never booked."""


class RetiredDesignError(EvaluationError):
    """A design id was retired and can never be reused."""


class BadDomainError(EvaluationError):
    """Task domain outside the pinned vocabulary."""


class BadMethodologyError(EvaluationError):
    """Methodology outside the pinned vocabulary."""


class BadRunKindError(EvaluationError):
    """Run kind outside the pinned vocabulary."""


class BadScoreError(EvaluationError):
    """Score outside the declared scale or not an int."""


class BadScaleError(EvaluationError):
    """Score scale not a positive int in range."""


class BadDigestError(EvaluationError):
    """Malformed sha256: digest pin."""


class BadReasonError(EvaluationError):
    """Retirement reason outside the pinned vocabulary."""


class DesignStateError(EvaluationError):
    """Mutation attempted against a design that is not live."""


class SeqOrderError(EvaluationError):
    """Caller seq did not strictly increase."""


class AuditKindError(EvaluationError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


def _normalize(score: int, scale: int) -> int:
    return round(100 * score / scale)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DesignRecord:
    """One declared eval protocol (digest pins only, never raw eval material)."""

    design_id: str
    task_domain: str
    methodology: str
    design_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "design_id": self.design_id,
            "task_domain": self.task_domain,
            "methodology": self.methodology,
            "design_digest": self.design_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "design_id": self.design_id,
                "task_domain": self.task_domain,
                "methodology": self.methodology,
                "design_digest": self.design_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RunRecord:
    """One declared eval run (host-reported score booked as data)."""

    run_id: str
    design_id: str
    run_kind: str
    score: int
    score_scale: int
    normalized: int
    run_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "design_id": self.design_id,
            "run_kind": self.run_kind,
            "score": self.score,
            "score_scale": self.score_scale,
            "normalized": self.normalized,
            "run_digest": self.run_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "run_id": self.run_id,
                "design_id": self.design_id,
                "run_kind": self.run_kind,
                "score": self.score,
                "score_scale": self.score_scale,
                "normalized": self.normalized,
                "run_digest": self.run_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a design (pinned reason)."""

    design_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "design_id": self.design_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "design_id": self.design_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class AnalysisReport:
    """Pure-read derived analysis of one design (verdict as ledger-rule data)."""

    design_id: str
    task_domain: str
    methodology: str
    n_runs: int
    mean_normalized: int
    min_normalized: int
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "design_id": self.design_id,
            "task_domain": self.task_domain,
            "methodology": self.methodology,
            "n_runs": self.n_runs,
            "mean_normalized": self.mean_normalized,
            "min_normalized": self.min_normalized,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "design_id": self.design_id,
                "task_domain": self.task_domain,
                "methodology": self.methodology,
                "n_runs": self.n_runs,
                "mean_normalized": self.mean_normalized,
                "min_normalized": self.min_normalized,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def evaluation_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the evaluation ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class Evaluation:
    """AI evaluation governance ledger (Simulated).

    ``design()`` / ``run()`` / ``retire()`` mutate the ledger and consume
    caller seqs; ``analyze()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._designs: Dict[str, DesignRecord] = {}
        self._runs: Dict[str, RunRecord] = {}
        self._runs_by_design: Dict[str, List[str]] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_runs = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = evaluation_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(evaluation_audit_event(audit_kind, seq, **details))

    def _live(self, design_id: str) -> DesignRecord:
        record = self._designs.get(design_id)
        if record is None:
            raise UnknownDesignError(f"unknown design: {design_id!r}")
        if design_id in self._retired:
            raise RetiredDesignError(f"design id retired forever: {design_id!r}")
        return record

    # -- design --------------------------------------------------------------

    def design(
        self,
        design_id: str,
        task_domain: str,
        seq: int,
        methodology: str = "held-out-suite",
        design_digest: str = "",
    ) -> DesignRecord:
        """Book one declared eval protocol (digest pins only)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(design_id, "design_id")
                if design_id in self._retired:
                    raise RetiredDesignError(
                        f"design id retired forever: {design_id!r}"
                    )
                if design_id in self._designs:
                    raise DuplicateDesignError(
                        f"duplicate design: {design_id!r}"
                    )
                if task_domain not in TASK_DOMAINS:
                    raise BadDomainError(f"bad task domain: {task_domain!r}")
                if methodology not in METHODOLOGIES:
                    raise BadMethodologyError(f"bad methodology: {methodology!r}")
                design_digest = _require_optional_digest(design_digest, "design_digest")
                record = DesignRecord(
                    design_id=design_id,
                    task_domain=task_domain,
                    methodology=methodology,
                    design_digest=design_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "design_id": design_id,
                            "task_domain": task_domain,
                            "methodology": methodology,
                            "design_digest": design_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._designs[design_id] = record
                self._emit(
                    "designed",
                    seq,
                    design_id=design_id,
                    task_domain=task_domain,
                    methodology=methodology,
                )
                return record
            except EvaluationError:
                self._burn(seq, "design", design_id=design_id)
                raise

    # -- run -----------------------------------------------------------------

    def run(
        self,
        design_id: str,
        seq: int,
        run_kind: str = "baseline",
        score: int = 0,
        score_scale: int = 100,
        run_digest: str = "",
    ) -> RunRecord:
        """Book one declared eval run against a live design (minted ``run-N``).

        The score is host-reported and booked as data; this method measures
        nothing and proves nothing about real capability.
        """
        with self._lock:
            self._claim(seq)
            try:
                self._live(design_id)
                if run_kind not in RUN_KINDS:
                    raise BadRunKindError(f"bad run kind: {run_kind!r}")
                if (
                    isinstance(score_scale, bool)
                    or not isinstance(score_scale, int)
                    or score_scale < 1
                    or score_scale > 10000
                ):
                    raise BadScaleError("score_scale must be an int in 1..10000")
                if (
                    isinstance(score, bool)
                    or not isinstance(score, int)
                    or score < 0
                    or score > score_scale
                ):
                    raise BadScoreError(
                        f"score must be an int in 0..{score_scale}"
                    )
                run_digest = _require_optional_digest(run_digest, "run_digest")
                self._n_runs += 1
                run_id = f"run-{self._n_runs}"
                normalized = _normalize(score, score_scale)
                record = RunRecord(
                    run_id=run_id,
                    design_id=design_id,
                    run_kind=run_kind,
                    score=score,
                    score_scale=score_scale,
                    normalized=normalized,
                    run_digest=run_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "run_id": run_id,
                            "design_id": design_id,
                            "run_kind": run_kind,
                            "score": score,
                            "score_scale": score_scale,
                            "normalized": normalized,
                            "run_digest": run_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._runs[run_id] = record
                self._runs_by_design.setdefault(design_id, []).append(run_id)
                self._emit(
                    "run_recorded",
                    seq,
                    design_id=design_id,
                    run_id=run_id,
                    run_kind=run_kind,
                    normalized=normalized,
                )
                return record
            except EvaluationError:
                self._burn(seq, "run", design_id=design_id)
                raise

    # -- retire ----------------------------------------------------------------

    def retire(
        self, design_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a design (pinned reason); ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(design_id, str) or not design_id:
                    raise BadIdError("design_id must be a non-empty str")
                if design_id in self._retired:
                    raise RetiredDesignError(
                        f"design id retired forever: {design_id!r}"
                    )
                if design_id not in self._designs:
                    raise UnknownDesignError(f"unknown design: {design_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                record = RetireRecord(
                    design_id=design_id,
                    reason=reason,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "design_id": design_id,
                            "reason": reason,
                            "seq": seq,
                        }
                    ),
                )
                self._retirements[design_id] = record
                self._retired.add(design_id)
                self._emit(
                    "retired",
                    seq,
                    design_id=design_id,
                    reason=reason,
                )
                return record
            except EvaluationError:
                self._burn(seq, "retire", design_id=design_id)
                raise

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def analyze(self, design_id: str, seq: int) -> AnalysisReport:
        """Derive a digest-pinned analysis for one design (pure read).

        The verdict is ledger-rule data, never measured truth:

        * ``unevaluated`` when no runs are booked;
        * ``fail`` when any booked run normalized below ``FAIL_MARK``;
        * ``pass`` when every booked run normalized at or above
          ``PASS_MARK``;
        * ``marginal`` otherwise.

        ``integrity_ok`` reports whether every stored record for the
        design still verifies (tamper reported, never raised).
        """
        with self._lock:
            self._view_seq_ok(seq)
            design = self._designs.get(design_id)
            if design is None:
                raise UnknownDesignError(f"unknown design: {design_id!r}")
            run_ids = self._runs_by_design.get(design_id, ())
            norms = [self._runs[rid].normalized for rid in run_ids]
            integrity_ok = design.verify()
            for rid in run_ids:
                integrity_ok = integrity_ok and self._runs[rid].verify()
            n_runs = len(run_ids)
            if n_runs == 0:
                verdict = "unevaluated"
                mean_normalized = 0
                min_normalized = 0
            else:
                mean_normalized = sum(norms) // n_runs
                min_normalized = min(norms)
                if any(n < FAIL_MARK for n in norms):
                    verdict = "fail"
                elif all(n >= PASS_MARK for n in norms):
                    verdict = "pass"
                else:
                    verdict = "marginal"
            report = AnalysisReport(
                design_id=design_id,
                task_domain=design.task_domain,
                methodology=design.methodology,
                n_runs=n_runs,
                mean_normalized=mean_normalized,
                min_normalized=min_normalized,
                verdict=verdict,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "design_id": design_id,
                        "task_domain": design.task_domain,
                        "methodology": design.methodology,
                        "n_runs": n_runs,
                        "mean_normalized": mean_normalized,
                        "min_normalized": min_normalized,
                        "verdict": verdict,
                        "integrity_ok": integrity_ok,
                        "seq": seq,
                    }
                ),
            )
            return report

    def design_record(self, design_id: str, seq: int) -> DesignRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._designs.get(design_id)
            if record is None:
                raise UnknownDesignError(f"unknown design: {design_id!r}")
            return record

    def run_record(self, run_id: str, seq: int) -> RunRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._runs.get(run_id)
            if record is None:
                raise UnknownRunError(f"unknown run: {run_id!r}")
            return record

    def runs_for(self, design_id: str, seq: int) -> Tuple[RunRecord, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if design_id not in self._designs:
                raise UnknownDesignError(f"unknown design: {design_id!r}")
            return tuple(
                self._runs[rid] for rid in self._runs_by_design.get(design_id, ())
            )

    def design_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._designs))

    def run_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._runs))

    def live_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                sorted(did for did in self._designs if did not in self._retired)
            )

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._retired))

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "designs": len(self._designs),
                "runs": len(self._runs),
                "live": len(self.live_ids(0)),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: this module imports stdlib (plus canonical_json) only."""
        import ast
        from pathlib import Path

        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "ast",
            "pathlib",
        }
        tree = ast.parse(Path(__file__).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports <= allowed


def main() -> None:
    pin = "sha256:" + "ab" * 32
    e = Evaluation()
    d = e.design("EV-1", "safety", 1, methodology="held-out-suite", design_digest=pin)
    r1 = e.run("EV-1", 2, run_kind="baseline", score=82, run_digest=pin)
    r2 = e.run("EV-1", 3, run_kind="elicitation", score=74, score_scale=100)
    a = e.analyze("EV-1", 0)
    assert d.verify() and r1.verify() and r2.verify() and a.verify()
    assert r1.run_id == "run-1" and r2.run_id == "run-2"
    assert r1.normalized == 82 and r2.normalized == 74
    assert a.n_runs == 2 and a.verdict == "pass" and a.integrity_ok is True
    e.retire("EV-1", 4, reason="protocol-complete")
    assert e.analyze("EV-1", 0).verdict == "pass"
    print("evaluation OK: design, run, analyze, pins, audit")


if __name__ == "__main__":
    main()
