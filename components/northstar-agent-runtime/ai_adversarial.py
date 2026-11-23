"""AI adversarial: adversarial test/defense decision ledger, Simulated.

Research note: adversarial machine learning is the study of how models
fail under crafted inputs - evasion, poisoning, extraction, backdoors,
inversion, membership inference, and sponge attacks - and how defenses
(adversarial training, input sanitization, randomized smoothing,
certified defenses) claim to harden them. This module is the *decision
ledger* for declared adversarial *testing*: which systems had which
adversarial tests booked (over pinned test-method and test-kind
vocabularies), what verdicts were declared against them, what defenses
the host declared, and what adversarial posture the ledger derives -
defensible bookkeeping, never proof that a system is really robust or
really vulnerable.

This module owns the test -> defend -> verify lifecycle:

* **test()** - book one declared adversarial test (minted ``tst-N`` ids;
  pinned test-method vocabulary over the common adversarial-testing
  methods; pinned test-kind vocabulary over the common adversarial
  classes; pinned verdict vocabulary booked *as data*); the first test
  registers its system; raw perturbations, gradients, samples, datasets,
  and material never enter records - digest pins only.
* **defend()** - book one declared defense against a booked test (minted
  ``def-N`` ids; pinned defense-strategy vocabulary booked *as data*);
  repeatable chain; books the *declaration*, never the deployed defense.
* **verify()** - **pure read**: re-derive one test/defense record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the test really ran.
* **evaluate()** - **pure read**: derive one system's adversarial
  posture as data (``untested`` -> ``vulnerable`` -> ``contested`` ->
  ``defended`` -> ``robust``) with verdict tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings:
``adversarial_detector.py`` owns detector *mechanics*;
``ai_attack.py`` owns the live-incident *attack* detection/defense
lifecycle over hostile AI-attack classes (prompt injection, jailbreak,
inference abuse, supply-chain) - this module is the *adversarial-testing*
decision ledger none of them own: declared adversarial test campaigns
over pinned test methods/kinds, declared defense deployments, digest
re-derivation, and the ledger-rule posture that turns declared verdicts
into a robustness claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-adversarial.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no attacks, tests no models, deploys no
defenses, and proves nothing about real adversarial robustness. A
booked ``vulnerable`` verdict means "the host declared it", never "the
model is exploitable"; a booked defense means "the host declared it",
never "the attack was stopped". Perturbations, gradients, datasets,
samples, and raw test material never enter records or cross the audit
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
AI_ADVERSARIAL_VERSION = "ai-adversarial.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-adversarial.v1"

#: Pinned adversarial-test-method vocabulary (the testing methods used).
TEST_METHODS = (
    "gradient-based",
    "optimization-based",
    "perturbation-based",
    "generative-attack",
    "query-based",
    "transfer-based",
    "physical-world",
    "poisoning-injection",
)

#: Pinned adversarial-test-kind vocabulary (the adversarial classes tested).
TEST_KINDS = (
    "evasion",
    "poisoning",
    "extraction",
    "backdoor",
    "inversion",
    "membership-inference",
    "model-stealing",
    "sponge",
)

#: Pinned test-verdict vocabulary (booked as data, never proof).
TEST_VERDICTS = (
    "vulnerable",
    "suspected",
    "robust",
    "inconclusive",
    "not-tested",
)

#: Pinned defense-strategy vocabulary (booked as data, never proof).
DEFENSE_STRATEGIES = (
    "adversarial-training",
    "input-sanitization",
    "randomized-smoothing",
    "certified-defense",
    "gradient-masking",
    "detection-filter",
    "ensemble-defense",
    "no-action",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "untested",
    "vulnerable",
    "contested",
    "defended",
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
    "defended",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "perturbation",
        "perturbations",
        "epsilon",
        "attack_budget",
        "adversarial_example",
        "adversarial_examples",
        "attack_samples",
        "attack_sample",
        "poisoned_data",
        "clean_data",
        "training_data",
        "test_split",
        "train_split",
        "dataset",
        "datasets",
        "sample",
        "samples",
        "trigger",
        "triggers",
        "backdoor",
        "backdoor_trigger",
        "gradient",
        "gradients",
        "activations",
        "logits",
        "embeddings",
        "weights",
        "model_weights",
        "parameters",
        "params",
        "query_log",
        "queries",
        "input_text",
        "output_text",
        "prompt",
        "prompts",
        "response",
        "responses",
        "transcript",
        "transcripts",
        "trace",
        "traces",
        "telemetry",
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "credentials",
        "credential",
        "password",
        "passwords",
        "api_key",
        "secret_key",
        "private_key",
        "token",
        "session_token",
        "auth",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "log",
        "logs",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIAdversarialError(Exception):
    """Base class for all ai-adversarial ledger errors."""


class BadSystemError(AIAdversarialError):
    pass


class UnknownSystemError(AIAdversarialError):
    pass


class RetiredSystemError(AIAdversarialError):
    pass


class BadTestMethodError(AIAdversarialError):
    pass


class BadTestKindError(AIAdversarialError):
    pass


class BadVerdictError(AIAdversarialError):
    pass


class BadSeverityError(AIAdversarialError):
    pass


class BadDigestError(AIAdversarialError):
    pass


class BadReasonError(AIAdversarialError):
    pass


class UnknownTestError(AIAdversarialError):
    pass


class UnknownDefenseError(AIAdversarialError):
    pass


class UnknownRecordError(AIAdversarialError):
    pass


class BadStrategyError(AIAdversarialError):
    pass


class SeqOrderError(AIAdversarialError):
    pass


class AuditKindError(AIAdversarialError):
    pass


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_test_method(value: Any) -> str:
    if value not in TEST_METHODS:
        raise BadTestMethodError(f"test_method must be one of {TEST_METHODS}")
    return value


def _check_test_kind(value: Any) -> str:
    if value not in TEST_KINDS:
        raise BadTestKindError(f"test_kind must be one of {TEST_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in TEST_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {TEST_VERDICTS}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in DEFENSE_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {DEFENSE_STRATEGIES}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be in [0, 100]")
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
class TestRecord:
    test_id: str
    system_id: str
    seq: int
    test_method: str
    test_kind: str
    verdict: str
    severity: int
    test_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _test_payload(self), "ai-adversarial.test"
        )


@dataclass(frozen=True)
class DefenseRecord:
    defense_id: str
    test_id: str
    system_id: str
    seq: int
    strategy: str
    defense_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _defend_payload(self), "ai-adversarial.defend"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-adversarial.retire"
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
            _verify_payload(self), "ai-adversarial.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_tests: int
    n_vulnerable: int
    n_suspected: int
    n_robust: int
    n_inconclusive: int
    n_not_tested: int
    n_defended: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-adversarial.evaluate"
        )


def _test_payload(rec: "TestRecord") -> Dict[str, Any]:
    return {
        "test_id": rec.test_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "test_method": rec.test_method,
        "test_kind": rec.test_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "test_digest": rec.test_digest,
    }


def _defend_payload(rec: "DefenseRecord") -> Dict[str, Any]:
    return {
        "defense_id": rec.defense_id,
        "test_id": rec.test_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "defense_digest": rec.defense_digest,
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
        "n_tests": rep.n_tests,
        "n_vulnerable": rep.n_vulnerable,
        "n_suspected": rep.n_suspected,
        "n_robust": rep.n_robust,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_tested": rep.n_not_tested,
        "n_defended": rep.n_defended,
        "integrity_ok": rep.integrity_ok,
    }


def ai_adversarial_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIAdversarialError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-adversarial",
        "version": AI_ADVERSARIAL_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIAdversarial:
    """AI adversarial test/defense decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and defenses
    are booked as data - never proof that a system is really robust or
    really vulnerable.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, TestRecord] = {}
        self._defenses: Dict[str, DefenseRecord] = {}
        self._system_tests: Dict[str, List[str]] = {}
        self._test_defenses: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._test_counter = 0
        self._defense_counter = 0
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
            row = ai_adversarial_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-adversarial",
                "version": AI_ADVERSARIAL_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_adversarial_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        test_method: str = "gradient-based",
        test_kind: str = "evasion",
        verdict: str = "not-tested",
        severity: int = 0,
        test_digest: str = "",
    ) -> TestRecord:
        """Book one declared adversarial test (minted ``tst-N`` id).

        The first test on an id registers the system. Raw
        perturbations, gradients, samples, datasets, and material never
        enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-adversarial.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                test_method = _check_test_method(test_method)
                test_kind = _check_test_kind(test_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                test_digest = _check_digest(test_digest, "test_digest")
                self._require_live(system_id)
            except AIAdversarialError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._test_counter += 1
            test_id = f"tst-{self._test_counter}"
            provisional = TestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                test_method=test_method,
                test_kind=test_kind,
                verdict=verdict,
                severity=severity,
                test_digest=test_digest,
                digest="",
            )
            digest = _digest_pin(_test_payload(provisional), "ai-adversarial.test")
            rec = TestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                test_method=test_method,
                test_kind=test_kind,
                verdict=verdict,
                severity=severity,
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
                test_method=test_method,
                test_kind=test_kind,
                verdict=verdict,
                severity=severity,
            )
            return rec

    def defend(
        self,
        test_id: str,
        seq: int,
        strategy: str = "no-action",
        defense_digest: str = "",
    ) -> DefenseRecord:
        """Book one declared defense against a booked test (minted ``def-N`` id).

        Books the *declaration*, never the deployed defense. Repeatable
        as a chain. Fail-closed: failed mutations consume their seq and
        book an ``ai-adversarial.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                test_id = _check_id(test_id, "test_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                defense_digest = _check_digest(defense_digest, "defense_digest")
                test = self._tests.get(test_id)
                if test is None:
                    raise UnknownTestError(f"unknown test: {test_id!r}")
                self._require_live(test.system_id)
            except AIAdversarialError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._defense_counter += 1
            defense_id = f"def-{self._defense_counter}"
            provisional = DefenseRecord(
                defense_id=defense_id,
                test_id=test_id,
                system_id=test.system_id,
                seq=seq,
                strategy=strategy,
                defense_digest=defense_digest,
                digest="",
            )
            digest = _digest_pin(_defend_payload(provisional), "ai-adversarial.defend")
            rec = DefenseRecord(
                defense_id=defense_id,
                test_id=test_id,
                system_id=test.system_id,
                seq=seq,
                strategy=strategy,
                defense_digest=defense_digest,
                digest=digest,
            )
            self._defenses[defense_id] = rec
            self._test_defenses.setdefault(test_id, []).append(defense_id)
            self._emit(
                "defended",
                seq,
                defense_id=defense_id,
                test_id=test_id,
                system_id=test.system_id,
                strategy=strategy,
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
            except AIAdversarialError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-adversarial.retire")
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
            and all(
                self._defenses[fid].verify()
                for fid in self._test_defenses.get(tid, [])
            )
            for tid in self._system_tests.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "vulnerable": 0,
            "suspected": 0,
            "robust": 0,
            "inconclusive": 0,
            "not-tested": 0,
            "defended": 0,
        }
        ids = self._system_tests.get(system_id, [])
        for tid in ids:
            rec = self._tests[tid]
            tallies[rec.verdict] += 1
            if self._test_defenses.get(tid):
                tallies["defended"] += 1
        if not ids:
            return "untested", tallies
        if any(
            self._tests[tid].verdict == "vulnerable"
            and not self._test_defenses.get(tid)
            for tid in ids
        ):
            return "vulnerable", tallies
        if tallies["suspected"] or tallies["inconclusive"]:
            return "contested", tallies
        if tallies["vulnerable"]:
            return "defended", tallies
        if all(self._tests[tid].verdict == "robust" for tid in ids):
            return "robust", tallies
        return "contested", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._tests.get(record_id) or self._defenses.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-adversarial.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's adversarial posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_tests:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_tests=len(self._system_tests[system_id]),
                n_vulnerable=tallies["vulnerable"],
                n_suspected=tallies["suspected"],
                n_robust=tallies["robust"],
                n_inconclusive=tallies["inconclusive"],
                n_not_tested=tallies["not-tested"],
                n_defended=tallies["defended"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-adversarial.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_tests=len(self._system_tests[system_id]),
                n_vulnerable=tallies["vulnerable"],
                n_suspected=tallies["suspected"],
                n_robust=tallies["robust"],
                n_inconclusive=tallies["inconclusive"],
                n_not_tested=tallies["not-tested"],
                n_defended=tallies["defended"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._tests.get(test_id)
            if rec is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            return rec

    def defense_record(self, defense_id: str, seq: int) -> DefenseRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._defenses.get(defense_id)
            if rec is None:
                raise UnknownDefenseError(f"unknown defense: {defense_id!r}")
            return rec

    def tests_for(self, system_id: str, seq: int) -> Tuple[TestRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._tests[tid] for tid in self._system_tests.get(system_id, [])
            )

    def defenses_for(self, test_id: str, seq: int) -> Tuple[DefenseRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._defenses[fid] for fid in self._test_defenses.get(test_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_tests.keys()))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._tests.keys()))

    def defense_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._defenses.keys()))

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
                "n_defenses": len(self._defenses),
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
    """Self-check: exercise test -> defend -> verify -> evaluate."""
    ledger = AIAdversarial()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.test(
        "sys-1",
        1,
        test_method="optimization-based",
        test_kind="evasion",
        verdict="vulnerable",
        severity=70,
    )
    assert rec.verify()
    dfn = ledger.defend(rec.test_id, 2, strategy="adversarial-training")
    assert dfn.verify()
    rep = ledger.verify(rec.test_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "defended"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-adversarial OK: test, defend, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
