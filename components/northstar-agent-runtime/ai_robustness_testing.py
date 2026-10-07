"""AI robustness testing: test-execution-run decision ledger, Simulated.

Research note: AI robustness testing is the practice of exercising a
system against perturbations it was not trained on - adversarial
examples, distribution shift, input corruptions, backdoor triggers,
jailbreak attempts and the like. This module is the *decision ledger*
for declared robustness test executions: which systems had which test
runs booked (over a pinned run-family vocabulary), what run outcomes
were declared against them, and what robustness posture the ledger
derives - defensible bookkeeping, never proof that a system is really
robust.

This module owns the test -> verify -> evaluate lifecycle:

* **test()** - book one declared robustness test run (minted ``run-N``
  ids; pinned 8-family run vocabulary; pinned outcome vocabulary
  booked *as data*); the first run registers its system; raw test
  material (perturbed inputs, attack prompts, traces, scores, weights)
  never enters records - digest pins only.
* **verify()** - **pure read**: re-derive one run record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof
  the run really executed.
* **evaluate()** - **pure read**: derive one system's robustness posture
  as data (``untested`` -> ``failed`` -> ``contested`` -> ``partial``
  -> ``robust``) with outcome tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_robustness.py`` owns the
robustness test-*governance* lifecycle (declared tests over the pinned
test-kind vocabulary, minted ``tst-N`` ids); ``robustness_testing.py``
owns the perturbation *mechanics* (declare target, declare perturbation
op, book stress trials); ``adversarial_robustness.py`` owns the
adversarial-probe lifecycle; ``ai_resilience.py`` owns resilience
assessments - this module is the test-*execution run* ledger none of
them own: declared runs of robustness test suites against a declared
system, per-run declared outcomes, digest-pinned run records, and the
ledger-rule posture that turns declared run outcomes into a robustness
claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-robustness-testing.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, executes no tests, inspects
no systems, and proves nothing about real AI robustness. A booked
``passed`` outcome means "the host declared it", never "the system
passed"; a booked ``failed`` outcome means "the host declared it",
never "the system is fragile". Test inputs, perturbed samples, attack
material, behavior traces, weights, and raw test material never enter
records or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_ROBUSTNESS_TESTING_VERSION = "ai-robustness-testing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-robustness-testing.v1"

#: Pinned test-run family vocabulary (the run families declared).
RUN_KINDS = (
    "adversarial-suite-run",
    "shift-suite-run",
    "corruption-suite-run",
    "backdoor-scan-run",
    "jailbreak-suite-run",
    "injection-suite-run",
    "poisoning-audit-run",
    "noise-tolerance-run",
)

#: Pinned run-outcome vocabulary (booked as data, never proof).
OUTCOMES = (
    "passed",
    "partial",
    "failed",
    "inconclusive",
    "not-run",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "untested",
    "failed",
    "contested",
    "partial",
    "robust",
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
    "tested",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "activations",
        "gradients",
        "embeddings",
        "attention",
        "attention_weights",
        # test-run raw material
        "test_input",
        "test_inputs",
        "perturbed_input",
        "perturbed_inputs",
        "perturbation",
        "perturbations",
        "adversarial_example",
        "adversarial_examples",
        "attack_prompt",
        "attack_prompts",
        "jailbreak_prompt",
        "trigger",
        "triggers",
        "backdoor_trigger",
        "corrupted_input",
        "noisy_input",
        "shift_sample",
        "shift_samples",
        "sample",
        "samples",
        "dataset",
        "benchmark_data",
        "eval_set",
        "test_suite",
        "suite_config",
        "config",
        "config_text",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "logits",
        "logit",
        "scores",
        "score_trace",
        "prediction",
        "behavior",
        "behavior_trace",
        "trace",
        "traces",
        "telemetry",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "recording",
        "recordings",
        "explanation",
        "saliency_map",
        "heatmap",
        "features",
        "feature_vector",
        "checkpoint_data",
        "weights_file",
        "command_output",
        "stderr",
        "stdout",
        "memory",
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "credential",
        "credentials",
        "password",
        "api_key",
        "secret",
        "token",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIRobustnessTestingError(Exception):
    """Base class for all ai-robustness-testing ledger errors."""


class BadInputError(AIRobustnessTestingError):
    pass


class UnknownSystemError(AIRobustnessTestingError):
    pass


class RetiredSystemError(AIRobustnessTestingError):
    pass


class BadRunKindError(AIRobustnessTestingError):
    pass


class BadOutcomeError(AIRobustnessTestingError):
    pass


class BadDigestError(AIRobustnessTestingError):
    pass


class BadReasonError(AIRobustnessTestingError):
    pass


class UnknownRunError(AIRobustnessTestingError):
    pass


class UnknownRecordError(AIRobustnessTestingError):
    pass


class SeqOrderError(AIRobustnessTestingError):
    pass


class AuditKindError(AIRobustnessTestingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value


def _check_run_kind(value: Any) -> str:
    if value not in RUN_KINDS:
        raise BadRunKindError(f"run_kind must be one of {RUN_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {OUTCOMES}")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RobustnessRunRecord:
    run_id: str
    system_id: str
    seq: int
    run_kind: str
    outcome: str
    test_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _run_payload(self), "ai-robustness-testing.test"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-robustness-testing.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-robustness-testing.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_runs: int
    n_passed: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-robustness-testing.evaluate"
        )


def _run_payload(rec: "RobustnessRunRecord") -> Dict[str, Any]:
    return {
        "run_id": rec.run_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "run_kind": rec.run_kind,
        "outcome": rec.outcome,
        "test_digest": rec.test_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_runs": rep.n_runs,
        "n_passed": rep.n_passed,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


def ai_robustness_testing_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIRobustnessTestingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-robustness-testing",
        "version": AI_ROBUSTNESS_TESTING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIRobustnessTesting:
    """AI robustness test-execution-run decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a run really executed or a system is robust.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._runs: Dict[str, RobustnessRunRecord] = {}
        self._system_runs: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._run_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_robustness_testing_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-robustness-testing",
                "version": AI_ROBUSTNESS_TESTING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_robustness_testing_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        run_kind: str = "adversarial-suite-run",
        outcome: str = "not-run",
        test_digest: str = "",
    ) -> RobustnessRunRecord:
        """Book one declared robustness test run (minted ``run-N`` id).

        The first run on an id registers the system. Raw test material
        (perturbed inputs, attack prompts, traces, scores, weights)
        never enters records - digest pins only. Fail-closed: failed
        mutations consume their seq and book an
        ``ai-robustness-testing.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                run_kind = _check_run_kind(run_kind)
                outcome = _check_outcome(outcome)
                test_digest = _check_digest(test_digest, "test_digest")
                self._require_live(system_id)
            except AIRobustnessTestingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._run_counter += 1
            run_id = f"run-{self._run_counter}"
            provisional = RobustnessRunRecord(
                run_id=run_id,
                system_id=system_id,
                seq=seq,
                run_kind=run_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest="",
            )
            digest = _digest_pin(
                _run_payload(provisional), "ai-robustness-testing.test"
            )
            rec = RobustnessRunRecord(
                run_id=run_id,
                system_id=system_id,
                seq=seq,
                run_kind=run_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest=digest,
            )
            self._runs[run_id] = rec
            self._system_runs.setdefault(system_id, []).append(run_id)
            self._emit(
                "tested",
                seq,
                run_id=run_id,
                system_id=system_id,
                run_kind=run_kind,
                outcome=outcome,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_runs:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIRobustnessTestingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-robustness-testing.retire"
            )
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._runs[rid].verify()
            for rid in self._system_runs.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "passed": 0,
            "partial": 0,
            "failed": 0,
            "inconclusive": 0,
            "not-run": 0,
        }
        ids = self._system_runs.get(system_id, [])
        for rid in ids:
            tallies[self._runs[rid].outcome] += 1
        if not ids:
            return "untested", tallies
        if tallies["failed"]:
            return "failed", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"] or tallies["not-run"]:
            return "partial", tallies
        return "robust", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._runs.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-robustness-testing.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's robustness posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_runs:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_runs=len(self._system_runs[system_id]),
                n_passed=tallies["passed"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional),
                "ai-robustness-testing.evaluate",
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_runs=len(self._system_runs[system_id]),
                n_passed=tallies["passed"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def run_record(self, run_id: str, seq: int) -> RobustnessRunRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._runs.get(run_id)
            if rec is None:
                raise UnknownRunError(f"unknown run: {run_id!r}")
            return rec

    def runs_for(self, system_id: str, seq: int) -> Tuple[RobustnessRunRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._runs[rid] for rid in self._system_runs.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_runs.keys()))

    def run_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._runs.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_runs),
                "n_runs": len(self._runs),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise test -> verify -> evaluate."""
    ledger = AIRobustnessTesting()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.test(
        "sys-1", 1, run_kind="adversarial-suite-run", outcome="passed"
    )
    assert rec.verify()
    rec2 = ledger.test(
        "sys-1", 2, run_kind="shift-suite-run", outcome="partial"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.run_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "partial"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-robustness-testing OK: test, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
