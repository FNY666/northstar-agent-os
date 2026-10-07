"""AI robustness: robustness test-governance decision ledger, Simulated.

Research note: AI robustness is the field concerned with how AI systems
behave outside their training distribution - under adversarial pressure,
distribution shift, perturbations, faults, and edge conditions. This
module is the *decision ledger* for declared AI-robustness tests: which
systems had which robustness tests booked (over a pinned test-kind
vocabulary), what outcomes the host declared against them, and what
robustness posture the ledger derives - defensible bookkeeping, never
proof that a system is really robust.

This module owns the test -> verify -> evaluate lifecycle:

* **test()** - book one declared robustness test (minted ``tst-N``
  ids; pinned test-kind vocabulary over the common robustness test
  classes; pinned outcome vocabulary booked *as data*); the first
  test registers its system; raw test material (perturbed inputs,
  traces, scores, weights) never enters records - digest pins only.
* **verify()** - **pure read**: re-derive one test record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the test really ran.
* **evaluate()** - **pure read**: derive one system's robustness
  posture as data (``untested`` -> ``fragile`` -> ``degraded`` ->
  ``contested`` -> ``unevaluated`` -> ``robust``) with outcome
  tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``robustness_testing.py`` owns
the perturbation *mechanics* (declare target, declare perturbation op,
book stress trials with host-reported scores, derive drop statistics);
``adversarial_robustness.py`` owns the adversarial-probe lifecycle;
``robustness_eval.py`` owns robustness evaluation-run bookkeeping -
this module is the AI-robustness test *governance* ledger none of them
own: declared tests over the pinned robustness test-kind vocabulary,
host-declared outcomes booked as data, digest re-derivation, and the
ledger-rule posture that turns declared outcomes into a robustness
claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-robustness.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, executes
no tests, and proves nothing about real AI robustness. A booked
``robust`` outcome means "the host declared it", never "the system is
robust". Test inputs, perturbed samples, behavior traces, weights,
prompts, and raw test material never enter records or cross the audit
boundary - digest pins only.
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
AI_ROBUSTNESS_VERSION = "ai-robustness.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-robustness.v1"

#: Pinned test-kind vocabulary (the robustness test classes booked).
TEST_KINDS = (
    "adversarial",
    "distribution-shift",
    "perturbation",
    "stress",
    "calibration",
    "uncertainty",
    "fault-injection",
    "regeneration",
)

#: Pinned test-outcome vocabulary (booked as data, never proof).
TEST_OUTCOMES = (
    "robust",
    "degraded",
    "fragile",
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
    "degraded",
    "contested",
    "unevaluated",
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
        "perturbation",
        "perturbations",
        "noise",
        "sample",
        "samples",
        "dataset",
        "example",
        "examples",
        "input",
        "inputs",
        "score",
        "scores",
        "metric",
        "metrics",
        "loss",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIRobustnessError(Exception):
    """Base class for all ai-robustness ledger errors."""


class BadSystemError(AIRobustnessError):
    pass


class UnknownSystemError(AIRobustnessError):
    pass


class RetiredSystemError(AIRobustnessError):
    pass


class BadTestKindError(AIRobustnessError):
    pass


class BadOutcomeError(AIRobustnessError):
    pass


class BadDigestError(AIRobustnessError):
    pass


class BadReasonError(AIRobustnessError):
    pass


class UnknownTestError(AIRobustnessError):
    pass


class UnknownRecordError(AIRobustnessError):
    pass


class SeqOrderError(AIRobustnessError):
    pass


class AuditKindError(AIRobustnessError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_test_kind(value: Any) -> str:
    if value not in TEST_KINDS:
        raise BadTestKindError(f"test_kind must be one of {TEST_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in TEST_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {TEST_OUTCOMES}")
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
class RobustnessTestRecord:
    test_id: str
    system_id: str
    seq: int
    test_kind: str
    outcome: str
    test_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _test_payload(self), "ai-robustness.test"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-robustness.retire"
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
            _verify_payload(self), "ai-robustness.verify"
        )


@dataclass(frozen=True)
class RobustnessEvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_tests: int
    n_robust: int
    n_degraded: int
    n_fragile: int
    n_inconclusive: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-robustness.evaluate"
        )


def _test_payload(rec: "RobustnessTestRecord") -> Dict[str, Any]:
    return {
        "test_id": rec.test_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "test_kind": rec.test_kind,
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


def _evaluate_payload(rep: "RobustnessEvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_tests": rep.n_tests,
        "n_robust": rep.n_robust,
        "n_degraded": rep.n_degraded,
        "n_fragile": rep.n_fragile,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


def ai_robustness_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIRobustnessError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-robustness",
        "version": AI_ROBUSTNESS_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIRobustness:
    """AI-robustness test-governance decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a system is really robust.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, RobustnessTestRecord] = {}
        self._system_tests: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._test_counter = 0
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
            row = ai_robustness_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-robustness",
                "version": AI_ROBUSTNESS_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_robustness_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        test_kind: str = "adversarial",
        outcome: str = "not-run",
        test_digest: str = "",
    ) -> RobustnessTestRecord:
        """Book one declared robustness test (minted ``tst-N`` id).

        The first test on an id registers the system. Raw test inputs,
        perturbed samples, traces, and scores never enter records -
        digest pins only. Fail-closed: failed mutations consume their
        seq and book an ``ai-robustness.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                test_kind = _check_test_kind(test_kind)
                outcome = _check_outcome(outcome)
                test_digest = _check_digest(test_digest, "test_digest")
                self._require_live(system_id)
            except AIRobustnessError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._test_counter += 1
            test_id = f"tst-{self._test_counter}"
            provisional = RobustnessTestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                test_kind=test_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest="",
            )
            digest = _digest_pin(_test_payload(provisional), "ai-robustness.test")
            rec = RobustnessTestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                test_kind=test_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest=digest,
            )
            self._tests[test_id] = rec
            self._system_tests.setdefault(system_id, []).append(test_id)
            self._emit(
                "tested",
                seq,
                test_id=test_id,
                system_id=system_id,
                test_kind=test_kind,
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
                if system_id not in self._system_tests:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIRobustnessError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-robustness.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._tests[tid].verify()
            for tid in self._system_tests.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "robust": 0,
            "degraded": 0,
            "fragile": 0,
            "inconclusive": 0,
            "not-run": 0,
        }
        ids = self._system_tests.get(system_id, [])
        for tid in ids:
            tallies[self._tests[tid].outcome] += 1
        if not ids:
            return "untested", tallies
        if tallies["fragile"]:
            return "fragile", tallies
        if tallies["degraded"]:
            return "degraded", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["not-run"]:
            return "unevaluated", tallies
        return "robust", tallies

    def verify(self, test_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one test record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._tests.get(test_id)
            if rec is None:
                raise UnknownRecordError(f"unknown test: {test_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=test_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-robustness.verify")
            return VerificationReport(
                record_id=test_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> RobustnessEvaluationReport:
        """Pure read: derive one system's robustness posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_tests:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = RobustnessEvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_tests=len(self._system_tests[system_id]),
                n_robust=tallies["robust"],
                n_degraded=tallies["degraded"],
                n_fragile=tallies["fragile"],
                n_inconclusive=tallies["inconclusive"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-robustness.evaluate"
            )
            return RobustnessEvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_tests=len(self._system_tests[system_id]),
                n_robust=tallies["robust"],
                n_degraded=tallies["degraded"],
                n_fragile=tallies["fragile"],
                n_inconclusive=tallies["inconclusive"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def test_record(self, test_id: str, seq: int) -> RobustnessTestRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._tests.get(test_id)
            if rec is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            return rec

    def tests_for(self, system_id: str, seq: int) -> Tuple[RobustnessTestRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._tests[tid] for tid in self._system_tests.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_tests.keys()))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._tests.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_tests),
                "n_tests": len(self._tests),
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
    """Self-check: exercise test -> verify -> evaluate -> retire."""
    ledger = AIRobustness()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.test("sys-1", 1, test_kind="adversarial", outcome="robust")
    assert rec.verify()
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "robust"
    ret = ledger.retire("sys-1", 4)
    assert ret.verify()
    print("ai-robustness OK: test, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
