"""AI stress testing: declared stress-regime decision ledger, Simulated.

Research note: AI stress testing is the resilience-side complement of AI
testing - declared executions of declared stress regimes (load spikes,
throughput saturation, resource exhaustion, chaos injection, adversarial
bursts, latency degradation, failover storms, sustained overload) against
declared AI systems, with declared stability outcomes (stable, degraded,
failed, inconclusive, not-run). This module is the *decision ledger* for
declared stress runs: which systems had which stress runs booked (over a
pinned stress-kind vocabulary and a pinned outcome vocabulary), what
stability outcomes were declared, and what stress posture the ledger
derives - defensible bookkeeping, never proof that any system is really
resilient.

This module owns the stress -> verify -> evaluate lifecycle:

* **stress()** - book one declared stress execution run (minted ``sts-N``
  ids; pinned stress-kind and outcome vocabularies booked *as data*);
  the first run on an id registers the system; raw stress material, load
  profiles, traffic models, chaos configs, load traces, latency samples,
  failure dumps, and crash reports never enter records - digest pins
  only.
* **verify()** - **pure read**: re-derive one stress record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof
  the stress run really happened.
* **evaluate()** - **pure read**: derive one system's stress posture as
  data (``untested`` -> ``fragile`` -> ``contested`` -> ``degraded``
  -> ``resilient``) with outcome tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: the testing ledger
(``ai_testing.py``) owns declared per-run test executions of declared
systems; the red-teaming ledger (``ai_redteaming.py``) owns declared
adversarial exercises; the recovery ledger (``ai_recovery.py``) owns
post-incident recovery actions; the robustness-testing mechanics
(``robustness_testing.py``) own perturbation execution - this module is
the *stress-regime* ledger none of them own: declared stress executions
of declared systems against a pinned stress-kind vocabulary, digest
re-derivation of those runs, and the ledger-rule posture that turns
declared runs into a stability claim, always as data, never as measured
resilience.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-stress-testing.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs nothing, stresses nothing, and proves
nothing about real-world system resilience. A booked ``stable`` posture
means "the host declared it", never "the system survives stress"; a
booked ``failed`` outcome means "the host declared it", never "the
system truly failed". Load profiles, traffic models, chaos configs,
burst configs, failure dumps, latency samples, throughput logs, crash
reports, weights, and raw execution traces never enter records or cross
the audit boundary - digest pins only.
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
AI_STRESS_TESTING_VERSION = "ai-stress-testing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-stress-testing.v1"

#: Pinned stress-kind vocabulary (the kinds of declared stress runs).
STRESS_KINDS = (
    "load-spike",
    "throughput-saturation",
    "resource-exhaustion",
    "chaos-injection",
    "adversarial-burst",
    "latency-degradation",
    "failover-storm",
    "sustained-overload",
)

#: Pinned stress-outcome vocabulary (booked as data, never proof).
STRESS_OUTCOMES = (
    "stable",
    "degraded",
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
    "fragile",
    "contested",
    "degraded",
    "resilient",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "stressed",
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
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "postmortem",
        "root_cause",
        "harm",
        "harm_description",
        "damage",
        "damages",
        "remedy_text",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "training_data",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
        # stress-specific raw material
        "load_profile",
        "load_profiles",
        "stress_config",
        "chaos_config",
        "burst_config",
        "traffic_model",
        "failure_dump",
        "heap_dump",
        "core_dump",
        "stack_trace",
        "thread_dump",
        "metrics_stream",
        "latency_samples",
        "throughput_log",
        "error_log",
        "crash_report",
        "chaos_experiment",
        "experiment_config",
        "sla",
        "sla_report",
        "capacity_plan",
        "scalability_report",
        "endurance_log",
        "soak_log",
        "stress_material",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIStressTestingError(Exception):
    """Base class for all ai-stress-testing ledger errors."""


class BadSystemError(AIStressTestingError):
    pass


class UnknownSystemError(AIStressTestingError):
    pass


class RetiredSystemError(AIStressTestingError):
    pass


class BadStressKindError(AIStressTestingError):
    pass


class BadOutcomeError(AIStressTestingError):
    pass


class BadDigestError(AIStressTestingError):
    pass


class BadReasonError(AIStressTestingError):
    pass


class UnknownStressError(AIStressTestingError):
    pass


class SeqOrderError(AIStressTestingError):
    pass


class AuditKindError(AIStressTestingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_stress_kind(value: Any) -> str:
    if value not in STRESS_KINDS:
        raise BadStressKindError(f"stress_kind must be one of {STRESS_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in STRESS_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {STRESS_OUTCOMES}")
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StressRecord:
    stress_id: str
    system_id: str
    seq: int
    stress_kind: str
    outcome: str
    stress_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _stress_payload(self), "ai-stress-testing.stress"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-stress-testing.retire"
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
            _verify_payload(self), "ai-stress-testing.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_runs: int
    n_stable: int
    n_degraded: int
    n_failed: int
    n_inconclusive: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-stress-testing.evaluate"
        )


def _stress_payload(rec: "StressRecord") -> Dict[str, Any]:
    return {
        "stress_id": rec.stress_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "stress_kind": rec.stress_kind,
        "outcome": rec.outcome,
        "stress_digest": rec.stress_digest,
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
        "n_stable": rep.n_stable,
        "n_degraded": rep.n_degraded,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_stress_testing_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIStressTestingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-stress-testing",
        "version": AI_STRESS_TESTING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIStressTesting:
    """AI stress-testing declared-execution decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any system really survived stress.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._runs: Dict[str, StressRecord] = {}
        self._system_runs: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._stress_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
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
            row = ai_stress_testing_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-stress-testing",
                "version": AI_STRESS_TESTING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_stress_testing_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def stress(
        self,
        system_id: str,
        seq: int,
        stress_kind: str = "load-spike",
        outcome: str = "stable",
        stress_digest: str = "",
    ) -> StressRecord:
        """Book one declared stress execution run (minted ``sts-N`` id).

        The first run on an id registers the system. Raw stress material,
        load profiles, traffic models, chaos configs, load traces, and
        failure dumps never enter records - digest pins only.
        Fail-closed: failed mutations consume their seq and book an
        ``ai-stress-testing.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                stress_kind = _check_stress_kind(stress_kind)
                outcome = _check_outcome(outcome)
                stress_digest = _check_digest(stress_digest, "stress_digest")
                self._require_live(system_id)
            except AIStressTestingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._stress_counter += 1
            stress_id = f"sts-{self._stress_counter}"
            provisional = StressRecord(
                stress_id=stress_id,
                system_id=system_id,
                seq=seq,
                stress_kind=stress_kind,
                outcome=outcome,
                stress_digest=stress_digest,
                digest="",
            )
            digest = _digest_pin(
                _stress_payload(provisional), "ai-stress-testing.stress"
            )
            rec = StressRecord(
                stress_id=stress_id,
                system_id=system_id,
                seq=seq,
                stress_kind=stress_kind,
                outcome=outcome,
                stress_digest=stress_digest,
                digest=digest,
            )
            self._runs[stress_id] = rec
            self._system_runs.setdefault(system_id, []).append(stress_id)
            self._emit(
                "stressed",
                seq,
                stress_id=stress_id,
                system_id=system_id,
                stress_kind=stress_kind,
                outcome=outcome,
                stress_digest=stress_digest,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
                if system_id not in self._system_runs:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
            except AIStressTestingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-stress-testing.retire"
            )
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, stress_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one stress record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the stress run really happened. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(stress_id, bool)
                or not isinstance(stress_id, str)
                or stress_id not in self._runs
            ):
                raise UnknownStressError(f"unknown stress id: {stress_id!r}")
            rec = self._runs[stress_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=stress_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-stress-testing.verify"
            )
            return VerificationReport(
                record_id=stress_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's stress posture as data.

        Posture by ledger rule: ``untested`` (nothing booked) ->
        ``fragile`` (any failed) -> ``contested`` (any inconclusive) ->
        ``degraded`` (any degraded or not-run) -> ``resilient`` (all
        stable). ``integrity_ok`` re-derives all in-scope digest pins as
        data. Seq is shape-validated only - never consumed, no audit
        row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_runs:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            ids = self._system_runs[system_id]
            recs = [self._runs[i] for i in ids]
            n_stable = sum(1 for r in recs if r.outcome == "stable")
            n_degraded = sum(1 for r in recs if r.outcome == "degraded")
            n_failed = sum(1 for r in recs if r.outcome == "failed")
            n_inconclusive = sum(1 for r in recs if r.outcome == "inconclusive")
            n_not_run = sum(1 for r in recs if r.outcome == "not-run")
            if n_failed:
                posture = "fragile"
            elif n_inconclusive:
                posture = "contested"
            elif n_degraded or n_not_run:
                posture = "degraded"
            elif n_stable and n_stable == len(recs):
                posture = "resilient"
            else:
                posture = "untested"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_runs=len(recs),
                n_stable=n_stable,
                n_degraded=n_degraded,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                n_not_run=n_not_run,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-stress-testing.evaluate"
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_runs=len(recs),
                n_stable=n_stable,
                n_degraded=n_degraded,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                n_not_run=n_not_run,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def stress_record(self, stress_id: str, seq: int) -> StressRecord:
        with self._lock:
            self._check_read_seq(seq)
            if stress_id not in self._runs:
                raise UnknownStressError(f"unknown stress id: {stress_id!r}")
            return self._runs[stress_id]

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if system_id not in self._retired:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return self._retired[system_id]

    def stresses_for(self, system_id: str, seq: int) -> Tuple[StressRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._runs[i] for i in self._system_runs.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._system_runs))

    def stress_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._runs))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_systems": len(self._system_runs),
                "n_runs": len(self._runs),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_STRESS_TESTING_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise stress -> verify -> evaluate."""
    ledger = AIStressTesting()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.stress(
        "system-1",
        1,
        stress_kind="load-spike",
        outcome="stable",
    )
    assert rec.verify()
    rep = ledger.verify(rec.stress_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("system-1", 3)
    assert ev.posture == "resilient"
    ret = ledger.retire("system-1", 4)
    assert ret.verify()
    print("ai-stress-testing OK: stress, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
