"""Membership inference assessment ledger (privacy governance layer, NOT real MIA).

Research context: membership inference attacks (MIA) let an adversary decide
whether a specific record was in a model's training set, typically by
exploiting memorization through loss, confidence, or shadow-model behavior.
This module is the **governance layer** over MIA *testing*: it books declared
test campaigns, derives privacy-leakage metrics from host-reported trial
outcomes, and books declared mitigations. It is deliberately distinct from
the sibling layer on this tree:

* ``membership_inference_detector.py`` — query-shape tripwire: owns the
  *detection* half ("these logged queries look like MIA data collection",
  tripwires on repeated queries / confidence probing / shadow batches).
  It knows nothing about test campaigns, advantage math, or mitigation.

This module owns the *assessment* half: model registration, booking
simulated attack campaigns with declared outcomes (as data), deriving
true-positive / false-positive / advantage statistics, assessing leakage
risk, and booking mitigations. It runs no model, observes no training data,
performs no real attack: booked "advantages" are ledger truth about what the
host *declared*, never proof of real memorization.

Deterministic single-host state machine, house style throughout:

* frozen dataclasses, caller int seqs strictly increasing (claim-then-burn:
  failed mutations consume their seq and book
  ``membership-inference.rejected``; rewinds raise bare without consuming);
* no wall-clock, RLock-guarded, fail-closed taxonomy, stdlib-only with the
  ``canonical_json`` try/except fallback, ``sha256:`` digest pins, exact
  fraction arithmetic (``num/den`` text, no floats), ``audit.ndjson/1``
  events with raw content banned from the audit boundary;
* honest scope: metrics are arithmetic over declared trials — a host that
  books flattering trials gets flattering metrics; ``test()`` books the
  declaration, never a real attack.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Module version.
MEMBERSHIP_INFERENCE_VERSION = "membership-inference.v1"

#: Schema pin carried by records and audit events.
MEMBERSHIP_INFERENCE_SCHEMA = "northstar.membership-inference.v1"

#: Digest prefix for pins.
_DIGEST_PREFIX = "sha256:"

#: Domain separator so pins cannot collide with other digests.
_HASH_DOMAIN = b"northstar.membership-inference.v1\x00"

#: Pinned attack-kind vocabulary for booked test campaigns.
ATTACK_KINDS = (
    "loss-threshold",
    "shadow-model",
    "likelihood-ratio",
    "confidence-score",
)

#: Pinned trial-outcome vocabulary (predicted label, ground truth).
#: tp: predicted member, actually member
#: fp: predicted member, actually non-member
#: tn: predicted non-member, actually non-member
#: fn: predicted non-member, actually member
TRIAL_OUTCOMES = ("tp", "fp", "tn", "fn")

#: Pinned mitigation vocabulary.
MITIGATIONS = (
    "dp-noise",
    "regularization",
    "deduplication",
    "early-stopping",
    "output-rounding",
    "temperature-scaling",
    "query-throttling",
)

#: Pinned retire reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "leakage-accepted",
    "model-withdrawn",
    "superseded",
    "compromised",
)

#: Pinned risk-band vocabulary for assessments.
RISK_BANDS = ("low", "moderate", "high")

#: Advantage at or above this is a "high" leak; below LOW is "low".
ADVANTAGE_HIGH = Fraction(3, 10)
ADVANTAGE_LOW = Fraction(1, 10)

#: Audit event kinds.
KIND_REGISTERED = "model-registered"
KIND_TESTED = "test-booked"
KIND_MITIGATED = "mitigation-booked"
KIND_RETIRED = "model-retired"
KIND_REJECTED = "membership-inference.rejected"

_KINDS = frozenset({
    KIND_REGISTERED, KIND_TESTED, KIND_MITIGATED, KIND_RETIRED,
    KIND_REJECTED,
})

#: Raw-content keys banned from the audit boundary (exact-key match).
_BANNED_KEYS = frozenset({
    "input", "inputs", "sample", "samples", "record", "records",
    "text", "content", "data", "payload", "value", "values",
    "raw", "plaintext", "secret", "training", "dataset",
})


# --------------------------------------------------------------------------
# Error taxonomy (fail-closed).
# --------------------------------------------------------------------------

class MembershipInferenceError(Exception):
    """Base error for membership-inference ledger misuse."""


class BadIdError(MembershipInferenceError):
    """A model/test/mitigation id was malformed (non-str or empty)."""


class DuplicateIdError(MembershipInferenceError):
    """The id is already booked (ids are never recycled)."""


class UnknownModelError(MembershipInferenceError):
    """Referenced model is not registered or is retired."""


class UnknownTestError(MembershipInferenceError):
    """Referenced test campaign does not exist."""


class RetiredModelError(MembershipInferenceError):
    """The model id was retired; all later mutations are refused forever."""


class BadKindError(MembershipInferenceError):
    """An attack kind / mitigation / reason / outcome was outside its vocabulary."""


class BadDigestError(MembershipInferenceError):
    """A digest was not a ``sha256:<64hex>`` pin (or allowed empty)."""


class BadTrialError(MembershipInferenceError):
    """A trial entry was malformed or empty where non-empty was required."""


class BadReasonError(MembershipInferenceError):
    """A retire reason was outside the pinned vocabulary."""


class SeqOrderError(MembershipInferenceError):
    """Caller seq was not strictly increasing (rewind/duplicate), or malformed."""


class AuditKindError(MembershipInferenceError):
    """The audit builder was called with an unknown kind."""


# --------------------------------------------------------------------------
# Small validators.
# --------------------------------------------------------------------------

def _check_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError("seq must be an int")
    return value


def _check_digest(value: object, name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be a str")
    if value == "" and allow_empty:
        return value
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise BadDigestError(f"{name} must be a {_DIGEST_PREFIX}<64hex> pin")
    try:
        int(value[len(_DIGEST_PREFIX):], 16)
    except ValueError:
        raise BadDigestError(f"{name} must be a {_DIGEST_PREFIX}<64hex> pin")
    return value


def _digest_pin(payload: object) -> str:
    """Deterministic ``sha256:`` pin over a canonical encoding of payload."""
    if _cj is not None:
        try:
            raw = _cj.jcs_dumps(payload).encode("utf-8")
        except Exception:
            raw = repr(payload).encode("utf-8")
    else:
        raw = repr(payload).encode("utf-8")
    digest = hashlib.sha256(_HASH_DOMAIN + raw).hexdigest()
    return _DIGEST_PREFIX + digest


def _frac_text(frac: Fraction) -> str:
    frac = Fraction(frac)
    return f"{frac.numerator}/{frac.denominator}"


# --------------------------------------------------------------------------
# Frozen records.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ModelRecord:
    """One model under MIA assessment."""

    model_id: str
    model_digest: str  # "" allowed (undeclared); otherwise sha256: pin
    training_size: int  # 0 = undeclared
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MEMBERSHIP_INFERENCE_SCHEMA,
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "training_size": self.training_size,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _digest_pin({
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "training_size": self.training_size,
            "seq": self.seq,
        })
        return expect == self.digest


@dataclass(frozen=True)
class TestRecord:
    """One booked (simulated) membership-inference test campaign.

    ``trials`` are outcome tokens (``tp``/``fp``/``tn``/``fn``) as data —
    the host's declared predictions against ground truth, never verified.
    """

    test_id: str
    model_id: str
    attack_kind: str
    trials: Tuple[str, ...]
    trials_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MEMBERSHIP_INFERENCE_SCHEMA,
            "test_id": self.test_id,
            "model_id": self.model_id,
            "attack_kind": self.attack_kind,
            "trials": list(self.trials),
            "trials_digest": self.trials_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _digest_pin({
            "test_id": self.test_id,
            "model_id": self.model_id,
            "attack_kind": self.attack_kind,
            "trials": list(self.trials),
            "trials_digest": self.trials_digest,
            "seq": self.seq,
        })
        return expect == self.digest


@dataclass(frozen=True)
class MitigationRecord:
    """One booked mitigation for a model."""

    mitigation_id: str
    model_id: str
    mitigation: str
    detail_digest: str  # "" allowed; otherwise sha256: pin
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MEMBERSHIP_INFERENCE_SCHEMA,
            "mitigation_id": self.mitigation_id,
            "model_id": self.model_id,
            "mitigation": self.mitigation,
            "detail_digest": self.detail_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _digest_pin({
            "mitigation_id": self.mitigation_id,
            "model_id": self.model_id,
            "mitigation": self.mitigation,
            "detail_digest": self.detail_digest,
            "seq": self.seq,
        })
        return expect == self.digest


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a model."""

    model_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MEMBERSHIP_INFERENCE_SCHEMA,
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _digest_pin({
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
        })
        return expect == self.digest


@dataclass(frozen=True)
class AssessmentReport:
    """Pure-read privacy-leakage assessment for a model (never raises on
    missing tests — reports ``low`` over zero evidence as data)."""

    model_id: str
    test_ids: Tuple[str, ...]
    total_trials: int
    tpr: str  # exact fraction text
    fpr: str  # exact fraction text
    advantage: str  # exact fraction text: tpr - fpr
    risk_band: str
    mitigations: Tuple[str, ...]
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MEMBERSHIP_INFERENCE_SCHEMA,
            "model_id": self.model_id,
            "test_ids": list(self.test_ids),
            "total_trials": self.total_trials,
            "tpr": self.tpr,
            "fpr": self.fpr,
            "advantage": self.advantage,
            "risk_band": self.risk_band,
            "mitigations": list(self.mitigations),
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _digest_pin({
            "model_id": self.model_id,
            "test_ids": list(self.test_ids),
            "total_trials": self.total_trials,
            "tpr": self.tpr,
            "fpr": self.fpr,
            "advantage": self.advantage,
            "risk_band": self.risk_band,
            "mitigations": list(self.mitigations),
            "seq": self.seq,
        })
        return expect == self.digest


# --------------------------------------------------------------------------
# Audit builder.
# --------------------------------------------------------------------------

def membership_inference_audit_event(audit_kind: str,
                                    detail: Dict[str, Any]) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event. Raw content keys are refused."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if not isinstance(detail, dict):
        raise AuditKindError("detail must be a dict")
    for key in detail:
        if key in _BANNED_KEYS:
            raise AuditKindError(f"banned key at audit boundary: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "module": MEMBERSHIP_INFERENCE_VERSION,
        "kind": audit_kind,
        "detail": dict(detail),
    }


# --------------------------------------------------------------------------
# The ledger.
# --------------------------------------------------------------------------

class MembershipInference:
    """Simulated MIA test/assess/mitigate lifecycle as a deterministic
    single-host state machine."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._models: Dict[str, ModelRecord] = {}
        self._tests: Dict[str, TestRecord] = {}
        self._tests_for_model: Dict[str, list] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._mitigations_for_model: Dict[str, list] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: list = []
        self._seq = 0

    # -- internal ---------------------------------------------------------

    def _claim(self, seq: int) -> None:
        """Claim-then-burn: seq must be strictly increasing; failed
        mutations have already consumed their seq before raising."""
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not above current {self._seq}")
        self._seq = seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        self._audit.append(
            membership_inference_audit_event(audit_kind, detail))

    def _reject(self, seq: int, reason: str) -> None:
        self._claim(seq)
        self._emit(KIND_REJECTED, {"reason": reason})

    def _live_model(self, model_id: str) -> ModelRecord:
        rec = self._models.get(model_id)
        if rec is None or model_id in self._retired:
            raise UnknownModelError(f"unknown or retired model: {model_id!r}")
        return rec

    # -- mutations ----------------------------------------------------------

    def register_model(self, model_id: str, seq: int,
                       model_digest: str = "",
                       training_size: int = 0) -> ModelRecord:
        _check_id(model_id, "model_id")
        _check_digest(model_digest, "model_digest", allow_empty=True)
        if isinstance(training_size, bool) or not isinstance(
                training_size, int) or training_size < 0:
            self._reject(seq, "bad-training-size")
            raise MembershipInferenceError("training_size must be a non-negative int")
        if model_id in self._models or model_id in self._retired:
            self._reject(seq, "duplicate-model-id")
            raise DuplicateIdError(f"model id already booked: {model_id!r}")
        self._claim(seq)
        digest = _digest_pin({
            "model_id": model_id,
            "model_digest": model_digest,
            "training_size": training_size,
            "seq": seq,
        })
        rec = ModelRecord(model_id=model_id, model_digest=model_digest,
                          training_size=training_size, seq=seq, digest=digest)
        self._models[model_id] = rec
        self._tests_for_model[model_id] = []
        self._mitigations_for_model[model_id] = []
        self._emit(KIND_REGISTERED, {
            "model_id": model_id,
            "model_digest": model_digest,
            "training_size": training_size,
        })
        return rec

    def test(self, test_id: str, model_id: str, attack_kind: str,
             seq: int, trials: Tuple[str, ...] = (),
             trials_digest: str = "") -> TestRecord:
        _check_id(test_id, "test_id")
        _check_id(model_id, "model_id")
        if attack_kind not in ATTACK_KINDS:
            self._reject(seq, "bad-attack-kind")
            raise BadKindError(f"attack_kind must be one of {ATTACK_KINDS}")
        try:
            self._live_model(model_id)
        except UnknownModelError:
            self._reject(seq, "unknown-model")
            raise
        if test_id in self._tests:
            self._reject(seq, "duplicate-test-id")
            raise DuplicateIdError(f"test id already booked: {test_id!r}")
        if not isinstance(trials, tuple) or not trials:
            self._reject(seq, "bad-trials")
            raise BadTrialError("trials must be a non-empty tuple")
        for trial in trials:
            if trial not in TRIAL_OUTCOMES:
                self._reject(seq, "bad-trial")
                raise BadTrialError(
                    f"trial must be one of {TRIAL_OUTCOMES}, got {trial!r}")
        _check_digest(trials_digest, "trials_digest", allow_empty=True)
        self._claim(seq)
        digest = _digest_pin({
            "test_id": test_id,
            "model_id": model_id,
            "attack_kind": attack_kind,
            "trials": list(trials),
            "trials_digest": trials_digest,
            "seq": seq,
        })
        rec = TestRecord(test_id=test_id, model_id=model_id,
                         attack_kind=attack_kind, trials=trials,
                         trials_digest=trials_digest, seq=seq, digest=digest)
        self._tests[test_id] = rec
        self._tests_for_model[model_id].append(test_id)
        self._emit(KIND_TESTED, {
            "test_id": test_id,
            "model_id": model_id,
            "attack_kind": attack_kind,
            "trial_count": len(trials),
        })
        return rec

    def assess(self, model_id: str, seq: int) -> AssessmentReport:
        """Pure read: derive leakage metrics from booked tests.

        seq shape is validated but never consumed; no audit row is written.
        Unknown or retired models report as data (``risk_band`` ``low``
        over zero evidence), never raised — assessments must not fail
        closed on missing history."""
        _check_id(model_id, "model_id")
        _check_seq(seq)
        test_ids = tuple(self._tests_for_model.get(model_id, ()))
        tp = fp = tn = fn = 0
        for tid in test_ids:
            for trial in self._tests[tid].trials:
                if trial == "tp":
                    tp += 1
                elif trial == "fp":
                    fp += 1
                elif trial == "tn":
                    tn += 1
                else:
                    fn += 1
        positives = tp + fn
        negatives = fp + tn
        tpr = Fraction(tp, positives) if positives else Fraction(0, 1)
        fpr = Fraction(fp, negatives) if negatives else Fraction(0, 1)
        advantage = tpr - fpr
        if advantage >= ADVANTAGE_HIGH:
            band = "high"
        elif advantage >= ADVANTAGE_LOW:
            band = "moderate"
        else:
            band = "low"
        mitigations = tuple(m.mitigation
                            for m in (self._mitigations[mid]
                                      for mid in self._mitigations_for_model.get(
                                          model_id, ())))
        digest = _digest_pin({
            "model_id": model_id,
            "test_ids": list(test_ids),
            "total_trials": tp + fp + tn + fn,
            "tpr": _frac_text(tpr),
            "fpr": _frac_text(fpr),
            "advantage": _frac_text(advantage),
            "risk_band": band,
            "mitigations": list(mitigations),
            "seq": seq,
        })
        return AssessmentReport(
            model_id=model_id, test_ids=test_ids,
            total_trials=tp + fp + tn + fn,
            tpr=_frac_text(tpr), fpr=_frac_text(fpr),
            advantage=_frac_text(advantage), risk_band=band,
            mitigations=mitigations, seq=seq, digest=digest)

    def mitigate(self, mitigation_id: str, model_id: str, mitigation: str,
                 seq: int, detail_digest: str = "") -> MitigationRecord:
        _check_id(mitigation_id, "mitigation_id")
        _check_id(model_id, "model_id")
        if mitigation not in MITIGATIONS:
            self._reject(seq, "bad-mitigation")
            raise BadKindError(f"mitigation must be one of {MITIGATIONS}")
        try:
            self._live_model(model_id)
        except UnknownModelError:
            self._reject(seq, "unknown-model")
            raise
        if mitigation_id in self._mitigations:
            self._reject(seq, "duplicate-mitigation-id")
            raise DuplicateIdError(
                f"mitigation id already booked: {mitigation_id!r}")
        _check_digest(detail_digest, "detail_digest", allow_empty=True)
        self._claim(seq)
        digest = _digest_pin({
            "mitigation_id": mitigation_id,
            "model_id": model_id,
            "mitigation": mitigation,
            "detail_digest": detail_digest,
            "seq": seq,
        })
        rec = MitigationRecord(mitigation_id=mitigation_id,
                               model_id=model_id, mitigation=mitigation,
                               detail_digest=detail_digest, seq=seq,
                               digest=digest)
        self._mitigations[mitigation_id] = rec
        self._mitigations_for_model[model_id].append(mitigation_id)
        self._emit(KIND_MITIGATED, {
            "mitigation_id": mitigation_id,
            "model_id": model_id,
            "mitigation": mitigation,
        })
        return rec

    def retire(self, model_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        _check_id(model_id, "model_id")
        if reason not in RETIRE_REASONS:
            self._reject(seq, "bad-reason")
            raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
        if model_id in self._retired:
            self._reject(seq, "already-retired")
            raise RetiredModelError(f"model already retired: {model_id!r}")
        try:
            self._live_model(model_id)
        except UnknownModelError:
            self._reject(seq, "unknown-model")
            raise
        self._claim(seq)
        digest = _digest_pin({
            "model_id": model_id,
            "reason": reason,
            "seq": seq,
        })
        rec = RetireRecord(model_id=model_id, reason=reason, seq=seq,
                           digest=digest)
        self._retired[model_id] = rec
        self._emit(KIND_RETIRED, {"model_id": model_id, "reason": reason})
        return rec

    # -- pure-read views ------------------------------------------------------

    def model_record(self, model_id: str, seq: int) -> ModelRecord:
        _check_id(model_id, "model_id")
        _check_seq(seq)
        rec = self._models.get(model_id)
        if rec is None:
            raise UnknownModelError(f"unknown model: {model_id!r}")
        return rec

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        _check_id(test_id, "test_id")
        _check_seq(seq)
        rec = self._tests.get(test_id)
        if rec is None:
            raise UnknownTestError(f"unknown test: {test_id!r}")
        return rec

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        _check_id(mitigation_id, "mitigation_id")
        _check_seq(seq)
        rec = self._mitigations.get(mitigation_id)
        if rec is None:
            raise MembershipInferenceError(
                f"unknown mitigation: {mitigation_id!r}")
        return rec

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._models))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._tests))

    def tests_for_model(self, model_id: str, seq: int) -> Tuple[str, ...]:
        _check_id(model_id, "model_id")
        _check_seq(seq)
        return tuple(self._tests_for_model.get(model_id, ()))

    def mitigations_for_model(self, model_id: str,
                              seq: int) -> Tuple[str, ...]:
        _check_id(model_id, "model_id")
        _check_seq(seq)
        return tuple(self._mitigations_for_model.get(model_id, ()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        _check_seq(seq)
        return {
            "models": len(self._models),
            "tests": len(self._tests),
            "mitigations": len(self._mitigations),
            "retired": len(self._retired),
            "audit_rows": len(self._audit),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        return tuple(self._audit)


# --------------------------------------------------------------------------
# Self-check.
# --------------------------------------------------------------------------

def main() -> int:
    ledger = MembershipInference()
    ledger.register_model("model-a", 1, training_size=1000)
    ledger.test("t-1", "model-a", "loss-threshold", 2,
                trials=("tp", "tp", "tp", "fn", "fn", "fn",
                        "fp", "fp", "fp", "tn", "tn", "tn", "tn",
                        "tn", "tn", "tn"))
    report = ledger.assess("model-a", 3)
    assert report.risk_band == "moderate", report.risk_band
    assert report.verify()
    ledger.mitigate("m-1", "model-a", "dp-noise", 4)
    ledger.retire("model-a", 5, reason="leakage-accepted")
    assert MEMBERSHIP_INFERENCE_VERSION == "membership-inference.v1"
    assert MEMBERSHIP_INFERENCE_SCHEMA == "northstar.membership-inference.v1"
    print("membership-inference OK: register, test, assess, mitigate, retire, pins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
