"""AI perturbation (perturb/verify/evaluate) interface, simulated.

Research motivation: robustness evaluation -- measuring how a model's
declared behavior holds up under input perturbations -- reduces to one
operational shape: the host declares a perturbation-test outcome over a
pinned perturbation-kind vocabulary, the ledger pins it, and a report
derives posture *from the ledger* -- the report never independently
judges whether the model is really robust to any perturbation.

This module is the *AI-perturbation* ledger half of that shape:

- ``AIPerturbation.perturb(system_id, seq, perturbation_kind="noise-injection", outcome="robust", perturbation_digest="")`` -- book one declared perturbation test over the pinned 8-kind vocabulary x the pinned 5-outcome vocabulary. The perturbed material is pinned by ``sha256:`` digest only; raw inputs, adversarial examples, perturbed samples, or model outputs never enter a record. First perturb on an id registers the system.
- ``AIPerturbation.verify(perturbation_id, seq)`` -- **pure read** (seq shape validated, never consumed, no audit row). Re-derives the digest pin; the ``verified``/``tampered`` verdict is *data*, never proof the perturbation test was really run or the model is really robust.
- ``AIPerturbation.evaluate(system_id, seq)`` -- **pure read**. Derives posture as data by ledger rule: ``untested`` (no perturbations) -> ``failed`` (any ``failed``) -> ``contested`` (any ``inconclusive``) -> ``degraded`` (any ``degraded`` or ``not-tested``) -> ``robust`` (all ``robust``), plus outcome tallies and ``integrity_ok`` as data.
- ``AIPerturbation.retire(system_id, seq, reason="manual")`` -- terminal. Ids are never recycled; post-retire mutations are refused, reads still work.
- Pure-read views (``perturbation_record`` / ``perturbations_for`` / ``system_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) -- seq shape validated, never consumed, no audit rows.
- ``ai_perturbation_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows (``perturbed`` / ``retired`` / ``rejected``); caller-supplied seqs only. Raw perturbation material never crosses the audit boundary -- audit rows carry ids, pinned perturbation-kind/outcome labels, digests, and counts only.

Distinct layer: ``robustness_testing.py`` owns perturbation *mechanics* (how perturbation suites run); ``ai_robustness.py`` owns robustness-test governance; adversarial-attack modules own attack mechanics; ``ai_fuzzing.py`` owns fuzzing mechanics. This module owns the AI *perturbation-test declaration* lifecycle none of them cover -- declared perturbation tests against pinned perturbation kinds, declared outcomes, ledger-rule posture.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``perturbation_id`` must be non-empty str, <= 256 chars, no whitespace.
- ``perturbation_kind`` must be in the pinned 8-kind vocabulary; ``outcome`` must be in the pinned 5-outcome vocabulary.
- ``perturbation_digest`` must be ``sha256:<64hex>`` when supplied (may be empty).
- ``perturb`` / ``verify`` on unknown ids raise; duplicate ids never occur (ids are minted ``prt-N``).
- ``perturb`` on a retired system raises ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance. Failed mutations consume their seq and book a ``rejected`` audit row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* perturbation tests reported by the host. A booked ``robust`` outcome means the host declared one -- the module perturbed nothing, measured nothing, and proves nothing about any real model's robustness to any real perturbation.
- Digest pins prove ledger integrity and ordering, never the truth of any declared perturbation outcome or the competence of any tester.
- No persistence: the ledger is in-memory. Pair with the durable audit writer if perturbation-test state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_PERTURBATION_VERSION = "ai-perturbation.v1"

#: Schema pin carried by records and audit events.
AI_PERTURBATION_SCHEMA = "northstar.ai-perturbation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_PERTURBED = "perturbed"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_PERTURBED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw material never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"input", "inputs", "sample", "samples", "perturbed_sample",
     "perturbed_input", "adversarial_example", "adversarial_prompt",
     "noise", "noise_vector", "corruption", "corrupted_input",
     "trigger", "backdoor_trigger", "payload", "prompt", "completion",
     "model_output", "logits", "activations", "embeddings", "weights",
     "gradients", "occlusion_mask", "perturbation", "perturbation_vector",
     "style", "style_transfer", "distribution", "shift",
     "dataset", "evidence", "report", "content", "text", "raw", "trace",
     "data", "record", "note", "transcript"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned perturbation-kind vocabulary (robustness-evaluation shaped).
KIND_NOISE_INJECTION = "noise-injection"
KIND_ADVERSARIAL_EXAMPLE = "adversarial-example"
KIND_INPUT_OCCLUSION = "input-occlusion"
KIND_STYLE_TRANSFER = "style-transfer"
KIND_BACKDOOR_TRIGGER = "backdoor-trigger"
KIND_PROMPT_INJECTION = "prompt-injection"
KIND_DISTRIBUTION_SHIFT = "distribution-shift"
KIND_CORRUPTION = "corruption"
PERTURBATION_KINDS = (
    KIND_NOISE_INJECTION,
    KIND_ADVERSARIAL_EXAMPLE,
    KIND_INPUT_OCCLUSION,
    KIND_STYLE_TRANSFER,
    KIND_BACKDOOR_TRIGGER,
    KIND_PROMPT_INJECTION,
    KIND_DISTRIBUTION_SHIFT,
    KIND_CORRUPTION,
)

#: Pinned perturbation outcome vocabulary. Outcomes are host-reported data.
OUTCOME_ROBUST = "robust"
OUTCOME_DEGRADED = "degraded"
OUTCOME_FAILED = "failed"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_NOT_TESTED = "not-tested"
OUTCOMES = (
    OUTCOME_ROBUST,
    OUTCOME_DEGRADED,
    OUTCOME_FAILED,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NOT_TESTED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNTESTED = "untested"
POSTURE_FAILED = "failed"
POSTURE_CONTESTED = "contested"
POSTURE_DEGRADED = "degraded"
POSTURE_ROBUST = "robust"
POSTURES = (
    POSTURE_UNTESTED,
    POSTURE_FAILED,
    POSTURE_CONTESTED,
    POSTURE_DEGRADED,
    POSTURE_ROBUST,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_SCOPE_CHANGE = "scope-change"
REASON_TEST_LOSS = "test-loss"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_SCOPE_CHANGE,
    REASON_TEST_LOSS,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AIPerturbationError(Exception):
    """Base error for the AI-perturbation ledger (programming errors)."""


class BadIdError(AIPerturbationError):
    """Raised when a system/perturbation id is malformed."""


class DuplicatePerturbationError(AIPerturbationError):
    """Raised when a minted perturbation id somehow collides (never)."""


class UnknownSystemError(AIPerturbationError):
    """Raised when a system id names no perturbed system."""


class UnknownPerturbationError(AIPerturbationError):
    """Raised when a perturbation id names no booked test."""


class RetiredSystemError(AIPerturbationError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AIPerturbationError):
    """Raised when retiring an already-retired system."""


class BadPerturbationKindError(AIPerturbationError):
    """Raised when a perturbation kind is not in the pinned vocabulary."""


class BadOutcomeError(AIPerturbationError):
    """Raised when an outcome is not in the pinned vocabulary."""


class BadDigestError(AIPerturbationError):
    """Raised when a perturbation digest is not a sha256: pin."""


class BadReasonError(AIPerturbationError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIPerturbationError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIPerturbationError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": AI_PERTURBATION_SCHEMA,
        "parts": list(parts),
    })


def ai_perturbation_audit_event(kind: str, detail: Dict[str, object],
                               seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-perturbation ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_PERTURBATION_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class PerturbationRecord:
    """Frozen record of one declared perturbation test (digest-pinned)."""
    perturbation_id: str
    system_id: str
    perturbation_kind: str
    outcome: str
    perturbation_digest: str
    seq: int
    digest: str

    def verify(self, perturbation_id: str, system_id: str,
               perturbation_kind: str, outcome: str,
               perturbation_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "perturbation", perturbation_id, system_id, perturbation_kind,
            outcome, perturbation_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    perturbation_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, perturbation_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", perturbation_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_perturbations: int
    n_robust: int
    n_degraded: int
    n_failed: int
    n_inconclusive: int
    n_not_tested: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, system_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", system_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, system_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", system_id, reason, self.seq)


class AIPerturbation:
    """AI-perturbation ledger (declared perturbation tests, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._perturbations: Dict[str, PerturbationRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._perturbation_ids: Tuple[str, ...] = ()
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, system_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if system_id:
            detail["system_id"] = system_id
        event = ai_perturbation_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_perturbation_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def perturb(self, system_id: str, seq: int,
                perturbation_kind: str = KIND_NOISE_INJECTION,
                outcome: str = OUTCOME_ROBUST,
                perturbation_digest: str = "") -> PerturbationRecord:
        """Book one declared perturbation test. First perturb on an id
        registers the system. Pins the perturbation digest, never the raw
        perturbation material. Returns the frozen ``PerturbationRecord``
        (minted ``prt-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(perturbation_kind, bool) or not isinstance(
                    perturbation_kind, str):
                raise BadPerturbationKindError(
                    f"perturbation_kind must be str, got "
                    f"{type(perturbation_kind).__name__}")
            if perturbation_kind not in PERTURBATION_KINDS:
                raise BadPerturbationKindError(
                    f"perturbation_kind must be one of "
                    f"{sorted(PERTURBATION_KINDS)}, got {perturbation_kind!r}")
            if isinstance(outcome, bool) or not isinstance(outcome, str):
                raise BadOutcomeError(
                    f"outcome must be str, got {type(outcome).__name__}")
            if outcome not in OUTCOMES:
                raise BadOutcomeError(
                    f"outcome must be one of {sorted(OUTCOMES)}, "
                    f"got {outcome!r}")
            perturbation_digest = _check_digest(
                perturbation_digest, "perturbation_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                perturbation_id = f"prt-{len(self._perturbation_ids) + 1}"
                if perturbation_id in self._perturbations:
                    raise DuplicatePerturbationError(
                        f"perturbation id collision: {perturbation_id!r}")
                record = PerturbationRecord(
                    perturbation_id=perturbation_id,
                    system_id=system_id,
                    perturbation_kind=perturbation_kind,
                    outcome=outcome,
                    perturbation_digest=perturbation_digest,
                    seq=seq,
                    digest=_pin("perturbation", perturbation_id, system_id,
                                perturbation_kind, outcome,
                                perturbation_digest, seq),
                )
                self._perturbations[perturbation_id] = record
                self._perturbation_ids = self._perturbation_ids + (
                    perturbation_id,)
                self._by_system[system_id] = (
                    self._by_system.get(system_id, ()) + (perturbation_id,))
        except AIPerturbationError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_PERTURBED,
                   {"system_id": system_id,
                    "perturbation_id": record.perturbation_id,
                    "perturbation_kind": perturbation_kind,
                    "outcome": outcome,
                    "perturbation_digest": perturbation_digest}, seq)
        return record

    def verify(self, perturbation_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a perturbation test's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        perturbation_id = _check_id(perturbation_id, "perturbation_id")
        with self._lock:
            if perturbation_id not in self._perturbations:
                raise UnknownPerturbationError(
                    f"unknown perturbation: {perturbation_id!r}")
            rec = self._perturbations[perturbation_id]
            intact = rec.verify(
                rec.perturbation_id, rec.system_id, rec.perturbation_kind,
                rec.outcome, rec.perturbation_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                perturbation_id=perturbation_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", perturbation_id, verdict, seq),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``failed`` -> ``failed``; any ``inconclusive`` ->
        ``contested``; any ``degraded`` or ``not-tested`` -> ``degraded``;
        all ``robust`` -> ``robust``). Validates seq shape, consumes
        nothing, writes no audit row. Returns the frozen
        ``EvaluationReport``."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            ids = self._by_system[system_id]
            recs = [self._perturbations[i] for i in ids]
            n_robust = sum(
                1 for r in recs if r.outcome == OUTCOME_ROBUST)
            n_degraded = sum(
                1 for r in recs if r.outcome == OUTCOME_DEGRADED)
            n_failed = sum(
                1 for r in recs if r.outcome == OUTCOME_FAILED)
            n_inconclusive = sum(
                1 for r in recs if r.outcome == OUTCOME_INCONCLUSIVE)
            n_not_tested = sum(
                1 for r in recs if r.outcome == OUTCOME_NOT_TESTED)
            integrity_ok = all(
                r.verify(r.perturbation_id, r.system_id,
                         r.perturbation_kind, r.outcome,
                         r.perturbation_digest) for r in recs)
            if n_failed:
                posture = POSTURE_FAILED
            elif n_inconclusive:
                posture = POSTURE_CONTESTED
            elif n_degraded or n_not_tested:
                posture = POSTURE_DEGRADED
            else:
                posture = POSTURE_ROBUST
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                n_perturbations=len(recs),
                n_robust=n_robust,
                n_degraded=n_degraded,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                n_not_tested=n_not_tested,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", system_id, posture, seq),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system. Ids are never recycled; post-retire
        mutations are refused, reads still work. Returns the frozen
        ``RetireRecord``."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                if system_id in self._retired:
                    raise DoubleRetireError(
                        f"system already retired: {system_id!r}")
                record = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", system_id, reason, seq),
                )
                self._retired[system_id] = record
        except AIPerturbationError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    def perturbation_record(self, perturbation_id: str,
                            seq: int) -> PerturbationRecord:
        """Pure read view of one booked perturbation test."""
        _check_seq(seq)
        perturbation_id = _check_id(perturbation_id, "perturbation_id")
        with self._lock:
            if perturbation_id not in self._perturbations:
                raise UnknownPerturbationError(
                    f"unknown perturbation: {perturbation_id!r}")
            return self._perturbations[perturbation_id]

    def perturbations_for(self, system_id: str,
                          seq: int) -> Tuple[str, ...]:
        """Pure read view of perturbation ids for one system, in book order."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered system ids, in first-perturb order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_system.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "systems": len(self._by_system),
                "perturbations": len(self._perturbations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: perturb, verify, evaluate, retire, pins, audit."""
    ap = AIPerturbation()
    assert AI_PERTURBATION_VERSION == "ai-perturbation.v1"
    assert AI_PERTURBATION_SCHEMA == "northstar.ai-perturbation.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = ap.perturb("sys-1", 1, KIND_NOISE_INJECTION, OUTCOME_ROBUST,
                     digest)
    assert rec.perturbation_id == "prt-1"
    assert rec.verify("prt-1", "sys-1", KIND_NOISE_INJECTION,
                      OUTCOME_ROBUST, digest)
    assert not rec.verify("prt-1", "sys-1", KIND_NOISE_INJECTION,
                          OUTCOME_FAILED, digest)
    vr = ap.verify("prt-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("prt-1", "verified")
    ev = ap.evaluate("sys-1", 3)
    assert ev.posture == POSTURE_ROBUST
    assert ev.integrity_ok
    rr = ap.retire("sys-1", 4)
    assert rr.system_id == "sys-1"
    assert rr.verify("sys-1", REASON_MANUAL)
    print("ai-perturbation OK: perturb, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
