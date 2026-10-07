"""AI calibration: calibration-method declaration decision ledger, Simulated.

Research note: calibration maps a model's confidence scores to empirical
accuracy - temperature scaling, Platt scaling, isotonic regression,
histogram binning, beta calibration and kin. This module is the *decision
ledger* for declared calibration runs: which models had which calibration
methods booked (over a pinned method vocabulary), what calibration verdicts
were declared against them, and what calibration posture the ledger derives
- defensible bookkeeping, never proof that a model is really calibrated.

This module owns the calibrate -> verify -> evaluate lifecycle:

* **calibrate()** - book one declared calibration run (minted ``cal-N``
  ids; pinned 8-method vocabulary; pinned verdict vocabulary booked *as
  data*; host-declared ``calibration_error`` int [0,100] booked as data);
  the first calibration registers its model; raw confidence scores,
  reliability diagrams, bins, and temperature values never enter records -
  digest pins only.
* **verify()** - **pure read**: re-derive one calibration record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the calibration was really performed.
* **evaluate()** - **pure read**: derive one model's calibration posture as
  data (``uncalibrated`` -> ``miscalibrated`` -> ``contested`` ->
  ``partial`` -> ``calibrated``) with verdict tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of a model id; ids are never
  recycled.

Distinct-layer rationale vs siblings: robustness and uncertainty ledgers
own perturbation mechanics and uncertainty quantification - this module is
the calibration-*method* declaration ledger none of them own: declared
calibration runs over the pinned calibration-method vocabulary, declared
calibration verdicts, and the ledger-rule posture that turns declared
verdicts into a calibration claim, always as data, never as measured
truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-calibration.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module calibrates nothing, inspects no model
internals, and proves nothing about real calibration. A booked
``calibrated`` verdict means "the host declared it", never "the model is
calibrated"; a booked ``miscalibrated`` verdict means "the host declared
it", never "the model is miscalibrated". Confidence scores, reliability
diagrams, bins, temperature values, and model internals never enter
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
AI_CALIBRATION_VERSION = "ai-calibration.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-calibration.v1"

#: Pinned calibration-method vocabulary (the method families declared).
CALIBRATION_METHODS = (
    "temperature-scaling",
    "platt-scaling",
    "isotonic-regression",
    "histogram-binning",
    "beta-calibration",
    "dirichlet-calibration",
    "bayesian-binning",
    "ensemble-calibration",
)

#: Pinned verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "calibrated",
    "partial",
    "miscalibrated",
    "inconclusive",
    "not-calibrated",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "uncalibrated",
    "miscalibrated",
    "contested",
    "partial",
    "calibrated",
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
    "calibrated",
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
        "logits",
        "logit",
        # calibration raw material
        "confidence_scores",
        "confidences",
        "probability_scores",
        "probabilities",
        "predicted_probabilities",
        "reliability_diagram",
        "calibration_curve",
        "bins",
        "bin_boundaries",
        "bin_counts",
        "temperature",
        "scaling_factor",
        "platt_params",
        "isotonic_curve",
        "regression_curve",
        "calibration_map",
        "calibration_function",
        "accuracy",
        "expected_accuracy",
        "empirical_accuracy",
        "predicted",
        "predictions",
        "labels",
        "gold_labels",
        "validation_set",
        "holdout_set",
        "dataset",
        "data",
        "scores",
        "score",
        "curve",
        "diagram",
        "plot",
        "figure",
        "error",
        "errors",
        "residuals",
        "attribution",
        "attributions",
        "features",
        "feature_importance",
        "feature_vector",
        "input_tokens",
        "tokens",
        "token_list",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "prediction",
        "explanation",
        "explanations",
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
        "command_output",
        "stderr",
        "stdout",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
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


class AICalibrationError(Exception):
    """Base class for all ai-calibration ledger errors."""


class BadInputError(AICalibrationError):
    pass


class UnknownModelError(AICalibrationError):
    pass


class RetiredModelError(AICalibrationError):
    pass


class BadMethodError(AICalibrationError):
    pass


class BadVerdictError(AICalibrationError):
    pass


class BadErrorError(AICalibrationError):
    pass


class BadDigestError(AICalibrationError):
    pass


class BadReasonError(AICalibrationError):
    pass


class UnknownCalibrationError(AICalibrationError):
    pass


class UnknownRecordError(AICalibrationError):
    pass


class SeqOrderError(AICalibrationError):
    pass


class AuditKindError(AICalibrationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value


def _check_method(value: Any) -> str:
    if value not in CALIBRATION_METHODS:
        raise BadMethodError(f"calibration_method must be one of {CALIBRATION_METHODS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERDICTS}")
    return value


def _check_error(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadErrorError("calibration_error must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadErrorError("calibration_error must be an int in [0, 100]")
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
class CalibrationRecord:
    calibration_id: str
    model_id: str
    seq: int
    calibration_method: str
    verdict: str
    calibration_error: int
    calibration_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _calibration_payload(self), "ai-calibration.calibrate"
        )


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-calibration.retire"
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
            _verify_payload(self), "ai-calibration.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    model_id: str
    seq: int
    posture: str
    n_calibrations: int
    n_calibrated: int
    n_partial: int
    n_miscalibrated: int
    n_inconclusive: int
    n_not_calibrated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-calibration.evaluate"
        )


def _calibration_payload(rec: "CalibrationRecord") -> Dict[str, Any]:
    return {
        "calibration_id": rec.calibration_id,
        "model_id": rec.model_id,
        "seq": rec.seq,
        "calibration_method": rec.calibration_method,
        "verdict": rec.verdict,
        "calibration_error": rec.calibration_error,
        "calibration_digest": rec.calibration_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"model_id": rec.model_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "model_id": rep.model_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_calibrations": rep.n_calibrations,
        "n_calibrated": rep.n_calibrated,
        "n_partial": rep.n_partial,
        "n_miscalibrated": rep.n_miscalibrated,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_calibrated": rep.n_not_calibrated,
        "integrity_ok": rep.integrity_ok,
    }


def ai_calibration_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AICalibrationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-calibration",
        "version": AI_CALIBRATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AICalibration:
    """AI calibration-method declaration decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts are booked as
    data - never proof that a model is really calibrated or miscalibrated.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._calibrations: Dict[str, CalibrationRecord] = {}
        self._model_calibrations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._calibration_counter = 0
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
            row = ai_calibration_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-calibration",
                "version": AI_CALIBRATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_calibration_audit_event(audit_kind, seq, **details))

    def _require_live(self, model_id: str) -> None:
        if model_id in self._retired:
            raise RetiredModelError(f"model is retired: {model_id!r}")

    # -- mutations ---------------------------------------------------------

    def calibrate(
        self,
        model_id: str,
        seq: int,
        calibration_method: str = "temperature-scaling",
        verdict: str = "not-calibrated",
        calibration_error: int = 0,
        calibration_digest: str = "",
    ) -> CalibrationRecord:
        """Book one declared calibration run (minted ``cal-N`` id).

        The first calibration on an id registers the model. Raw confidence
        scores, reliability diagrams, bins, and temperature values never
        enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-calibration.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                model_id = _check_id(model_id, "model_id")
                self._require_seq(seq)
                calibration_method = _check_method(calibration_method)
                verdict = _check_verdict(verdict)
                calibration_error = _check_error(calibration_error)
                calibration_digest = _check_digest(
                    calibration_digest, "calibration_digest"
                )
                self._require_live(model_id)
            except AICalibrationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._calibration_counter += 1
            calibration_id = f"cal-{self._calibration_counter}"
            provisional = CalibrationRecord(
                calibration_id=calibration_id,
                model_id=model_id,
                seq=seq,
                calibration_method=calibration_method,
                verdict=verdict,
                calibration_error=calibration_error,
                calibration_digest=calibration_digest,
                digest="",
            )
            digest = _digest_pin(
                _calibration_payload(provisional), "ai-calibration.calibrate"
            )
            rec = CalibrationRecord(
                calibration_id=calibration_id,
                model_id=model_id,
                seq=seq,
                calibration_method=calibration_method,
                verdict=verdict,
                calibration_error=calibration_error,
                calibration_digest=calibration_digest,
                digest=digest,
            )
            self._calibrations[calibration_id] = rec
            self._model_calibrations.setdefault(model_id, []).append(calibration_id)
            self._emit(
                "calibrated",
                seq,
                calibration_id=calibration_id,
                model_id=model_id,
                calibration_method=calibration_method,
                verdict=verdict,
                calibration_error=calibration_error,
            )
            return rec

    def retire(
        self, model_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a model id; ids are never recycled."""
        with self._lock:
            try:
                model_id = _check_id(model_id, "model_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if model_id not in self._model_calibrations:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if model_id in self._retired:
                    raise RetiredModelError(
                        f"model already retired: {model_id!r}"
                    )
            except AICalibrationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                model_id=model_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-calibration.retire")
            rec = RetireRecord(
                model_id=model_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[model_id] = rec
            self._emit("retired", seq, model_id=model_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, model_id: str) -> bool:
        return all(
            self._calibrations[cid].verify()
            for cid in self._model_calibrations.get(model_id, [])
        )

    def _posture(self, model_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "calibrated": 0,
            "partial": 0,
            "miscalibrated": 0,
            "inconclusive": 0,
            "not-calibrated": 0,
        }
        ids = self._model_calibrations.get(model_id, [])
        for cid in ids:
            tallies[self._calibrations[cid].verdict] += 1
        if not ids:
            return "uncalibrated", tallies
        if tallies["miscalibrated"]:
            return "miscalibrated", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"] or tallies["not-calibrated"]:
            return "partial", tallies
        return "calibrated", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._calibrations.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-calibration.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, model_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one model's calibration posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            model_id = _check_id(model_id, "model_id")
            if model_id not in self._model_calibrations:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            posture, tallies = self._posture(model_id)
            provisional = EvaluationReport(
                model_id=model_id,
                seq=seq,
                posture=posture,
                n_calibrations=len(self._model_calibrations[model_id]),
                n_calibrated=tallies["calibrated"],
                n_partial=tallies["partial"],
                n_miscalibrated=tallies["miscalibrated"],
                n_inconclusive=tallies["inconclusive"],
                n_not_calibrated=tallies["not-calibrated"],
                integrity_ok=self._integrity_ok(model_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-calibration.evaluate")
            return EvaluationReport(
                model_id=model_id,
                seq=seq,
                posture=posture,
                n_calibrations=len(self._model_calibrations[model_id]),
                n_calibrated=tallies["calibrated"],
                n_partial=tallies["partial"],
                n_miscalibrated=tallies["miscalibrated"],
                n_inconclusive=tallies["inconclusive"],
                n_not_calibrated=tallies["not-calibrated"],
                integrity_ok=self._integrity_ok(model_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def calibration_record(self, calibration_id: str, seq: int) -> CalibrationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._calibrations.get(calibration_id)
            if rec is None:
                raise UnknownCalibrationError(
                    f"unknown calibration: {calibration_id!r}"
                )
            return rec

    def calibrations_for(self, model_id: str, seq: int) -> Tuple[CalibrationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._calibrations[cid]
                for cid in self._model_calibrations.get(model_id, [])
            )

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._model_calibrations.keys()))

    def calibration_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._calibrations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_models": len(self._model_calibrations),
                "n_calibrations": len(self._calibrations),
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
    """Self-check: exercise calibrate -> verify -> evaluate."""
    ledger = AICalibration()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.calibrate(
        "mod-1",
        1,
        calibration_method="platt-scaling",
        verdict="calibrated",
        calibration_error=3,
    )
    assert rec.verify()
    rec2 = ledger.calibrate(
        "mod-1",
        2,
        calibration_method="temperature-scaling",
        verdict="partial",
        calibration_error=12,
    )
    assert rec2.verify()
    rep = ledger.verify(rec.calibration_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("mod-1", 4)
    assert ev.posture == "partial"
    ret = ledger.retire("mod-1", 5)
    assert ret.verify()
    print("ai-calibration OK: calibrate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
