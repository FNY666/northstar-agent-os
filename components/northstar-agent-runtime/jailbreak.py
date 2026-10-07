"""Jailbreak: red-team jailbreak test ledger, Simulated.

Research note: jailbreak testing is the red-team discipline of probing
whether an AI system can be steered past its refusal and policy
boundaries - prompt injection, roleplay coercion, encoding obfuscation,
multi-turn pressure, refusal suppression, and the rest of the published
technique taxonomy. The dangerous half of any such programme is the
*material*: the adversarial prompts, transcripts, and model outputs must
never be bundled with the bookkeeping record that tracks that a test was
run and what the operator declared its outcome to be.

This module is that bookkeeping layer, deliberately distinct from its
siblings ``adversarial_robustness.py`` (robustness scoring mechanics),
``adversarial_detector.py`` (detection heuristics), ``exploit_difficulty.py``
(difficulty modelling), and ``vuln_disclosure.py`` (coordinated disclosure
lifecycle): this module runs no model, crafts no adversarial prompt, and
leaks no attack content. It books:

* **test()** - declare one jailbreak test attempt (pinned technique and
  target-kind vocabulary; target, attempt, and technique material travel
  as ``sha256:`` digest pins only - raw prompts, transcripts, and model
  outputs never enter a record).
* **evaluate()** - book one declared outcome for an attempt, minted
  ``evl-N`` ids (outcome pinned to ``blocked`` / ``jailbroken`` /
  ``partial`` / ``inconclusive``, booked **as data** - never proof the
  target behaved as declared); one evaluation per attempt.
* **mitigate()** - book declared mitigations over the pinned action
  vocabulary as a repeatable chain, minted ``mit-N`` ids; books the
  *declaration*, never the fix.
* **retire()** - terminal bookkeeping for completed / decommissioned
  attempts; ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``jailbreak.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked test attempt is a host-declared claim, never proof
an attack was actually mounted; a booked "blocked" evaluation means the
host said so, never proof the model resisted; a booked mitigation is a
declared decision, never proof a guardrail was deployed or effective.
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
JAILBREAK_VERSION = "jailbreak.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.jailbreak.v1"

#: Pinned jailbreak technique vocabulary (published technique classes).
TECHNIQUES = (
    "prompt-injection",
    "roleplay-jailbreak",
    "encoding-obfuscation",
    "multi-turn-coercion",
    "refusal-suppression",
    "context-override",
    "token-smuggling",
    "jailbreak-template",
)

#: Pinned target-kind vocabulary (what was probed).
TARGET_KINDS = (
    "chat-model",
    "agent",
    "tool-interface",
    "vision-model",
)

#: Pinned evaluation-outcome vocabulary (booked as data).
OUTCOMES = (
    "blocked",
    "jailbroken",
    "partial",
    "inconclusive",
)

#: Pinned mitigation-action vocabulary.
MITIGATION_ACTIONS = (
    "patch-prompt-filter",
    "retrain-alignment",
    "add-guardrail",
    "tighten-policy",
    "monitor",
    "accept-risk",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "campaign-complete",
    "target-decommissioned",
    "superseded",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "tested",
    "evaluated",
    "mitigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "prompt",
        "attack",
        "exploit",
        "payload",
        "transcript",
        "response",
        "output",
        "content",
        "text",
        "raw",
        "input",
        "injection",
        "bypass",
        "technique_detail",
        "model_output",
        "user",
        "secret",
        "pii",
        "data",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class JailbreakError(Exception):
    """Base error for jailbreak ledger misuse."""


class BadIdError(JailbreakError):
    """Malformed attempt id."""


class DuplicateAttemptError(JailbreakError):
    """An attempt id was declared twice."""


class UnknownAttemptError(JailbreakError):
    """Reference to an attempt id that was never declared."""


class RetiredAttemptError(JailbreakError):
    """An attempt id was retired and can never be reused."""


class BadTechniqueError(JailbreakError):
    """Technique outside the pinned vocabulary."""


class BadTargetError(JailbreakError):
    """Target kind outside the pinned vocabulary."""


class BadOutcomeError(JailbreakError):
    """Evaluation outcome outside the pinned vocabulary."""


class BadActionError(JailbreakError):
    """Mitigation action outside the pinned vocabulary."""


class BadReasonError(JailbreakError):
    """Retirement reason outside the pinned vocabulary."""


class BadDigestError(JailbreakError):
    """Malformed sha256: digest pin."""


class AttemptStateError(JailbreakError):
    """Mutation attempted against an attempt that is not live."""


class AlreadyEvaluatedError(JailbreakError):
    """An attempt already carries an evaluation."""


class SeqOrderError(JailbreakError):
    """Caller seq did not strictly increase."""


class AuditKindError(JailbreakError):
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestRecord:
    """One declared jailbreak test attempt (digest pins only, never raw material)."""

    attempt_id: str
    technique: str
    target_kind: str
    target_digest: str
    attempt_digest: str
    technique_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "attempt_id": self.attempt_id,
            "technique": self.technique,
            "target_kind": self.target_kind,
            "target_digest": self.target_digest,
            "attempt_digest": self.attempt_digest,
            "technique_digest": self.technique_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "attempt_id": self.attempt_id,
                "technique": self.technique,
                "target_kind": self.target_kind,
                "target_digest": self.target_digest,
                "attempt_digest": self.attempt_digest,
                "technique_digest": self.technique_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationRecord:
    """One declared evaluation outcome for an attempt (booked as data)."""

    evaluation_id: str
    attempt_id: str
    outcome: str
    detail_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "evaluation_id": self.evaluation_id,
            "attempt_id": self.attempt_id,
            "outcome": self.outcome,
            "detail_digest": self.detail_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "evaluation_id": self.evaluation_id,
                "attempt_id": self.attempt_id,
                "outcome": self.outcome,
                "detail_digest": self.detail_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    """One declared mitigation against an attempt (booked as data)."""

    mitigation_id: str
    attempt_id: str
    action: str
    plan_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "attempt_id": self.attempt_id,
            "action": self.action,
            "plan_digest": self.plan_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "mitigation_id": self.mitigation_id,
                "attempt_id": self.attempt_id,
                "action": self.action,
                "plan_digest": self.plan_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an attempt (pinned reason)."""

    attempt_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "attempt_id": self.attempt_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "attempt_id": self.attempt_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class AttemptStatus:
    """Pure-read status of one attempt (digest-pinned, integrity as data)."""

    attempt_id: str
    technique: str
    target_kind: str
    outcome: str
    n_mitigations: int
    live: bool
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "attempt_id": self.attempt_id,
            "technique": self.technique,
            "target_kind": self.target_kind,
            "outcome": self.outcome,
            "n_mitigations": self.n_mitigations,
            "live": self.live,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "attempt_id": self.attempt_id,
                "technique": self.technique,
                "target_kind": self.target_kind,
                "outcome": self.outcome,
                "n_mitigations": self.n_mitigations,
                "live": self.live,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def jailbreak_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the jailbreak ledger."""
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


class Jailbreak:
    """Jailbreak red-team test ledger (Simulated).

    ``test()`` / ``evaluate()`` / ``mitigate()`` / ``retire()`` mutate the
    ledger and consume caller seqs; ``status()`` and all views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, TestRecord] = {}
        self._evaluations: Dict[str, EvaluationRecord] = {}
        self._evaluation_by_attempt: Dict[str, str] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._mitigations_by_attempt: Dict[str, List[str]] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_evaluations = 0
        self._n_mitigations = 0
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
            row = jailbreak_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(jailbreak_audit_event(audit_kind, seq, **details))

    def _live(self, attempt_id: str) -> TestRecord:
        record = self._tests.get(attempt_id)
        if record is None:
            raise UnknownAttemptError(f"unknown attempt: {attempt_id!r}")
        if attempt_id in self._retired:
            raise RetiredAttemptError(f"attempt id retired forever: {attempt_id!r}")
        return record

    # -- test --------------------------------------------------------------

    def test(
        self,
        attempt_id: str,
        technique: str,
        seq: int,
        target_kind: str = "chat-model",
        target_digest: str = "",
        attempt_digest: str = "",
        technique_digest: str = "",
    ) -> TestRecord:
        """Book one declared jailbreak test attempt (digest pins only)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(attempt_id, "attempt_id")
                if attempt_id in self._retired:
                    raise RetiredAttemptError(
                        f"attempt id retired forever: {attempt_id!r}"
                    )
                if attempt_id in self._tests:
                    raise DuplicateAttemptError(
                        f"duplicate attempt: {attempt_id!r}"
                    )
                if technique not in TECHNIQUES:
                    raise BadTechniqueError(f"bad technique: {technique!r}")
                if target_kind not in TARGET_KINDS:
                    raise BadTargetError(f"bad target kind: {target_kind!r}")
                target_digest = _require_optional_digest(target_digest, "target_digest")
                attempt_digest = _require_optional_digest(attempt_digest, "attempt_digest")
                technique_digest = _require_optional_digest(
                    technique_digest, "technique_digest"
                )
                record = TestRecord(
                    attempt_id=attempt_id,
                    technique=technique,
                    target_kind=target_kind,
                    target_digest=target_digest,
                    attempt_digest=attempt_digest,
                    technique_digest=technique_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "attempt_id": attempt_id,
                            "technique": technique,
                            "target_kind": target_kind,
                            "target_digest": target_digest,
                            "attempt_digest": attempt_digest,
                            "technique_digest": technique_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._tests[attempt_id] = record
                self._emit(
                    "tested",
                    seq,
                    attempt_id=attempt_id,
                    technique=technique,
                    target_kind=target_kind,
                )
                return record
            except JailbreakError:
                self._burn(seq, "test", attempt_id=attempt_id)
                raise

    # -- evaluate ------------------------------------------------------------

    def evaluate(
        self,
        attempt_id: str,
        seq: int,
        outcome: str = "blocked",
        detail_digest: str = "",
    ) -> EvaluationRecord:
        """Book one declared outcome for an attempt (minted ``evl-N`` ids)."""
        with self._lock:
            self._claim(seq)
            try:
                self._live(attempt_id)
                if attempt_id in self._evaluation_by_attempt:
                    raise AlreadyEvaluatedError(
                        f"attempt already evaluated: {attempt_id!r}"
                    )
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                detail_digest = _require_optional_digest(detail_digest, "detail_digest")
                self._n_evaluations += 1
                evaluation_id = f"evl-{self._n_evaluations}"
                record = EvaluationRecord(
                    evaluation_id=evaluation_id,
                    attempt_id=attempt_id,
                    outcome=outcome,
                    detail_digest=detail_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "evaluation_id": evaluation_id,
                            "attempt_id": attempt_id,
                            "outcome": outcome,
                            "detail_digest": detail_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._evaluations[evaluation_id] = record
                self._evaluation_by_attempt[attempt_id] = evaluation_id
                self._emit(
                    "evaluated",
                    seq,
                    attempt_id=attempt_id,
                    evaluation_id=evaluation_id,
                    outcome=outcome,
                )
                return record
            except JailbreakError:
                self._burn(seq, "evaluate", attempt_id=attempt_id)
                raise

    # -- mitigate ------------------------------------------------------------

    def mitigate(
        self,
        attempt_id: str,
        action: str,
        seq: int,
        plan_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation (repeatable chain, minted ``mit-N`` ids)."""
        with self._lock:
            self._claim(seq)
            try:
                self._live(attempt_id)
                if action not in MITIGATION_ACTIONS:
                    raise BadActionError(f"bad action: {action!r}")
                plan_digest = _require_optional_digest(plan_digest, "plan_digest")
                self._n_mitigations += 1
                mitigation_id = f"mit-{self._n_mitigations}"
                record = MitigationRecord(
                    mitigation_id=mitigation_id,
                    attempt_id=attempt_id,
                    action=action,
                    plan_digest=plan_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "mitigation_id": mitigation_id,
                            "attempt_id": attempt_id,
                            "action": action,
                            "plan_digest": plan_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._mitigations[mitigation_id] = record
                self._mitigations_by_attempt.setdefault(attempt_id, []).append(
                    mitigation_id
                )
                self._emit(
                    "mitigated",
                    seq,
                    attempt_id=attempt_id,
                    mitigation_id=mitigation_id,
                    action=action,
                )
                return record
            except JailbreakError:
                self._burn(seq, "mitigate", attempt_id=attempt_id)
                raise

    # -- retire ----------------------------------------------------------------

    def retire(
        self, attempt_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire an attempt (pinned reason); ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(attempt_id, str) or not attempt_id:
                    raise BadIdError("attempt_id must be a non-empty str")
                if attempt_id in self._retired:
                    raise RetiredAttemptError(
                        f"attempt id retired forever: {attempt_id!r}"
                    )
                if attempt_id not in self._tests:
                    raise UnknownAttemptError(f"unknown attempt: {attempt_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                record = RetireRecord(
                    attempt_id=attempt_id,
                    reason=reason,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "attempt_id": attempt_id,
                            "reason": reason,
                            "seq": seq,
                        }
                    ),
                )
                self._retirements[attempt_id] = record
                self._retired.add(attempt_id)
                self._emit(
                    "retired",
                    seq,
                    attempt_id=attempt_id,
                    reason=reason,
                )
                return record
            except JailbreakError:
                self._burn(seq, "retire", attempt_id=attempt_id)
                raise

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def status(self, attempt_id: str, seq: int) -> AttemptStatus:
        """Derive a digest-pinned status for one attempt (pure read).

        ``outcome`` is ``unevaluated`` until an evaluation is booked;
        ``integrity_ok`` and ``live`` are derived as data.
        """
        with self._lock:
            self._view_seq_ok(seq)
            record = self._tests.get(attempt_id)
            if record is None:
                raise UnknownAttemptError(f"unknown attempt: {attempt_id!r}")
            evaluation_id = self._evaluation_by_attempt.get(attempt_id)
            outcome = (
                self._evaluations[evaluation_id].outcome
                if evaluation_id is not None
                else "unevaluated"
            )
            n_mitigations = len(self._mitigations_by_attempt.get(attempt_id, ()))
            live = attempt_id not in self._retired
            integrity_ok = record.verify()
            if evaluation_id is not None:
                integrity_ok = integrity_ok and self._evaluations[
                    evaluation_id
                ].verify()
            for mid in self._mitigations_by_attempt.get(attempt_id, ()):
                integrity_ok = integrity_ok and self._mitigations[mid].verify()
            status = AttemptStatus(
                attempt_id=attempt_id,
                technique=record.technique,
                target_kind=record.target_kind,
                outcome=outcome,
                n_mitigations=n_mitigations,
                live=live,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "attempt_id": attempt_id,
                        "technique": record.technique,
                        "target_kind": record.target_kind,
                        "outcome": outcome,
                        "n_mitigations": n_mitigations,
                        "live": live,
                        "integrity_ok": integrity_ok,
                        "seq": seq,
                    }
                ),
            )
            return status

    def test_record(self, attempt_id: str, seq: int) -> TestRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._tests.get(attempt_id)
            if record is None:
                raise UnknownAttemptError(f"unknown attempt: {attempt_id!r}")
            return record

    def evaluation_record(self, evaluation_id: str, seq: int) -> EvaluationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._evaluations.get(evaluation_id)
            if record is None:
                raise UnknownAttemptError(f"unknown evaluation: {evaluation_id!r}")
            return record

    def evaluation_for(self, attempt_id: str, seq: int) -> EvaluationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            evaluation_id = self._evaluation_by_attempt.get(attempt_id)
            if evaluation_id is None:
                raise UnknownAttemptError(f"no evaluation for {attempt_id!r}")
            return self._evaluations[evaluation_id]

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._mitigations.get(mitigation_id)
            if record is None:
                raise UnknownAttemptError(f"unknown mitigation: {mitigation_id!r}")
            return record

    def mitigations_for(self, attempt_id: str, seq: int) -> Tuple[MitigationRecord, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                self._mitigations[mid]
                for mid in self._mitigations_by_attempt.get(attempt_id, ())
            )

    def attempt_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._tests))

    def evaluation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._evaluations))

    def mitigation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._mitigations))

    def evaluated_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._evaluation_by_attempt))

    def live_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(aid for aid in self._tests if aid not in self._retired))

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
                "attempts": len(self._tests),
                "evaluations": len(self._evaluations),
                "mitigations": len(self._mitigations),
                "live": len(self.live_ids(0)),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    pin = "sha256:" + "ab" * 32
    j = Jailbreak()
    t = j.test(
        "JB-1",
        "prompt-injection",
        1,
        target_kind="chat-model",
        target_digest=pin,
        attempt_digest=pin,
        technique_digest=pin,
    )
    e = j.evaluate("JB-1", 2, outcome="blocked", detail_digest=pin)
    m = j.mitigate("JB-1", "patch-prompt-filter", 3, plan_digest=pin)
    s = j.status("JB-1", 0)
    assert t.verify() and e.verify() and m.verify() and s.verify()
    assert e.evaluation_id == "evl-1"
    assert m.mitigation_id == "mit-1"
    assert s.outcome == "blocked" and s.n_mitigations == 1 and s.live is True
    j.retire("JB-1", 4, reason="campaign-complete")
    retired = j.status("JB-1", 0)
    assert retired.live is False
    print("jailbreak OK: test, evaluate, mitigate, pins, audit")


if __name__ == "__main__":
    main()
