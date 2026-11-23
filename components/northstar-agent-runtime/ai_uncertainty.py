"""AI uncertainty: uncertainty-quantification decision ledger, Simulated.

Research note: modern models ship calibrated-sounding confidences that may
be miscalibrated - epistemic vs aleatoric decomposition, calibration error
(ECE), conformal prediction sets, ensemble spread, MC-dropout, and
out-of-distribution uncertainty scores are the standard quantification
families. This module is the *decision ledger* for declared uncertainty
quantifications: which subjects had which uncertainty quantifications booked
(over a pinned uncertainty-kind vocabulary), what calibration verdicts were
declared against them, and what trust posture the ledger derives -
defensible bookkeeping, never proof that a model's uncertainty is really
well-calibrated.

This module owns the quantify -> verify -> evaluate lifecycle:

* **quantify()** - book one declared uncertainty quantification (minted
  ``unc-N`` ids; pinned 8-kind uncertainty vocabulary; pinned verdict
  vocabulary booked *as data*); the first quantification registers its
  subject; raw model outputs, scores, distributions, and sample traces
  never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one quantification record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the quantification was really run.
* **evaluate()** - **pure read**: derive one subject's uncertainty posture
  as data (``unexamined`` -> ``miscalibrated`` -> ``contested`` ->
  ``partially-calibrated`` -> ``calibrated``) with verdict tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a subject id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the
assessment->mitigation lifecycle, ``ai_verification.py`` owns
verify/certify checks against declared specifications, ``ai_testing.py``
owns test-run bookkeeping, ``ai_robustness.py`` owns robustness-test
governance - this module is the uncertainty-*quantification* decision
ledger none of them own: declared uncertainty quantifications over the
pinned uncertainty-kind vocabulary, declared calibration verdicts, and the
ledger-rule posture that turns declared verdicts into a trust claim,
always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-uncertainty.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module quantifies no uncertainty, inspects no model
outputs, and proves nothing about real calibration. A booked
``well-calibrated`` verdict means "the host declared it", never "the model
is calibrated"; a booked ``miscalibrated`` verdict means "the host declared
it", never "the model is miscalibrated". Model outputs, probability
distributions, confidence scores, sample traces, and calibration data
never enter records or cross the audit boundary - digest pins only.
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
AI_UNCERTAINTY_VERSION = "ai-uncertainty.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-uncertainty.v1"

#: Pinned uncertainty-kind vocabulary (the quantification families declared).
UNCERTAINTY_KINDS = (
    "epistemic",
    "aleatoric",
    "predictive",
    "calibration-error",
    "conformal",
    "ensemble-spread",
    "dropout-mc",
    "ood-uncertainty",
)

#: Pinned verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "well-calibrated",
    "overconfident",
    "underconfident",
    "miscalibrated",
    "not-assessed",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unexamined",
    "miscalibrated",
    "contested",
    "partially-calibrated",
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
    "quantified",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values, declared scalars such as ``score``, and digest pins remain
#: emittable as declared data).
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
        "attention_maps",
        # uncertainty raw material
        "model_output",
        "model_outputs",
        "outputs",
        "output",
        "predictions",
        "prediction",
        "logits",
        "logit",
        "probabilities",
        "probability",
        "probs",
        "distribution",
        "distributions",
        "samples",
        "sample_trace",
        "sample_traces",
        "mc_samples",
        "monte_carlo",
        "ensemble_predictions",
        "ensemble",
        "dropout_masks",
        "confidence_scores",
        "confidences",
        "uncertainty_values",
        "uncertainty_scores",
        "uncertainty_map",
        "calibration_data",
        "calibration_curve",
        "reliability_diagram",
        "ece",
        "expected_calibration_error",
        "conformal_sets",
        "prediction_sets",
        "coverage",
        "labels",
        "ground_truth",
        "dataset",
        "eval_data",
        "scores",
        "score_list",
        "features",
        "feature_vector",
        "prompt",
        "prompts",
        "response",
        "responses",
        "input",
        "input_data",
        "tokens",
        "token_list",
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
        "checkpoint_data",
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


class AIUncertaintyError(Exception):
    """Base class for all ai-uncertainty ledger errors."""


class BadInputError(AIUncertaintyError):
    pass


class UnknownSubjectError(AIUncertaintyError):
    pass


class RetiredSubjectError(AIUncertaintyError):
    pass


class BadKindError(AIUncertaintyError):
    pass


class BadVerdictError(AIUncertaintyError):
    pass


class BadScoreError(AIUncertaintyError):
    pass


class BadDigestError(AIUncertaintyError):
    pass


class BadReasonError(AIUncertaintyError):
    pass


class UnknownUncertaintyError(AIUncertaintyError):
    pass


class UnknownRecordError(AIUncertaintyError):
    pass


class SeqOrderError(AIUncertaintyError):
    pass


class AuditKindError(AIUncertaintyError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value


def _check_kind(value: Any) -> str:
    if value not in UNCERTAINTY_KINDS:
        raise BadKindError(f"uncertainty_kind must be one of {UNCERTAINTY_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERDICTS}")
    return value


def _check_score(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("score must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadScoreError("score must be an int in [0, 100]")
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
class UncertaintyRecord:
    uncertainty_id: str
    subject_id: str
    seq: int
    uncertainty_kind: str
    verdict: str
    score: int
    uncertainty_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _uncertainty_payload(self), "ai-uncertainty.quantify"
        )


@dataclass(frozen=True)
class RetireRecord:
    subject_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-uncertainty.retire"
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
            _verify_payload(self), "ai-uncertainty.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    subject_id: str
    seq: int
    posture: str
    n_quantifications: int
    n_well_calibrated: int
    n_overconfident: int
    n_underconfident: int
    n_miscalibrated: int
    n_not_assessed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-uncertainty.evaluate"
        )


def _uncertainty_payload(rec: "UncertaintyRecord") -> Dict[str, Any]:
    return {
        "uncertainty_id": rec.uncertainty_id,
        "subject_id": rec.subject_id,
        "seq": rec.seq,
        "uncertainty_kind": rec.uncertainty_kind,
        "verdict": rec.verdict,
        "score": rec.score,
        "uncertainty_digest": rec.uncertainty_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"subject_id": rec.subject_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "subject_id": rep.subject_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_quantifications": rep.n_quantifications,
        "n_well_calibrated": rep.n_well_calibrated,
        "n_overconfident": rep.n_overconfident,
        "n_underconfident": rep.n_underconfident,
        "n_miscalibrated": rep.n_miscalibrated,
        "n_not_assessed": rep.n_not_assessed,
        "integrity_ok": rep.integrity_ok,
    }


def ai_uncertainty_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIUncertaintyError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-uncertainty",
        "version": AI_UNCERTAINTY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIUncertainty:
    """AI uncertainty-quantification decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts are booked as
    data - never proof that a model is really well-calibrated or
    miscalibrated.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._uncertainties: Dict[str, UncertaintyRecord] = {}
        self._subject_uncertainties: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._uncertainty_counter = 0
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
            row = ai_uncertainty_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-uncertainty",
                "version": AI_UNCERTAINTY_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_uncertainty_audit_event(audit_kind, seq, **details))

    def _require_live(self, subject_id: str) -> None:
        if subject_id in self._retired:
            raise RetiredSubjectError(f"subject is retired: {subject_id!r}")

    # -- mutations ---------------------------------------------------------

    def quantify(
        self,
        subject_id: str,
        seq: int,
        uncertainty_kind: str = "epistemic",
        verdict: str = "not-assessed",
        score: int = 0,
        uncertainty_digest: str = "",
    ) -> UncertaintyRecord:
        """Book one declared uncertainty quantification (minted ``unc-N`` id).

        The first quantification on an id registers the subject. Raw model
        outputs, probability distributions, confidence scores, and sample
        traces never enter records - digest pins only. Fail-closed: failed
        mutations consume their seq and book an ``ai-uncertainty.rejected``
        row; rewinds raise bare.
        """
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                uncertainty_kind = _check_kind(uncertainty_kind)
                verdict = _check_verdict(verdict)
                score = _check_score(score)
                uncertainty_digest = _check_digest(
                    uncertainty_digest, "uncertainty_digest"
                )
                self._require_live(subject_id)
            except AIUncertaintyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._uncertainty_counter += 1
            uncertainty_id = f"unc-{self._uncertainty_counter}"
            provisional = UncertaintyRecord(
                uncertainty_id=uncertainty_id,
                subject_id=subject_id,
                seq=seq,
                uncertainty_kind=uncertainty_kind,
                verdict=verdict,
                score=score,
                uncertainty_digest=uncertainty_digest,
                digest="",
            )
            digest = _digest_pin(
                _uncertainty_payload(provisional), "ai-uncertainty.quantify"
            )
            rec = UncertaintyRecord(
                uncertainty_id=uncertainty_id,
                subject_id=subject_id,
                seq=seq,
                uncertainty_kind=uncertainty_kind,
                verdict=verdict,
                score=score,
                uncertainty_digest=uncertainty_digest,
                digest=digest,
            )
            self._uncertainties[uncertainty_id] = rec
            self._subject_uncertainties.setdefault(subject_id, []).append(
                uncertainty_id
            )
            self._emit(
                "quantified",
                seq,
                uncertainty_id=uncertainty_id,
                subject_id=subject_id,
                uncertainty_kind=uncertainty_kind,
                verdict=verdict,
                score=score,
            )
            return rec

    def retire(
        self, subject_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a subject id; ids are never recycled."""
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if subject_id not in self._subject_uncertainties:
                    raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
                if subject_id in self._retired:
                    raise RetiredSubjectError(
                        f"subject already retired: {subject_id!r}"
                    )
            except AIUncertaintyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-uncertainty.retire"
            )
            rec = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[subject_id] = rec
            self._emit("retired", seq, subject_id=subject_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, subject_id: str) -> bool:
        return all(
            self._uncertainties[uid].verify()
            for uid in self._subject_uncertainties.get(subject_id, [])
        )

    def _posture(self, subject_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "well-calibrated": 0,
            "overconfident": 0,
            "underconfident": 0,
            "miscalibrated": 0,
            "not-assessed": 0,
        }
        ids = self._subject_uncertainties.get(subject_id, [])
        for uid in ids:
            tallies[self._uncertainties[uid].verdict] += 1
        if not ids:
            return "unexamined", tallies
        if tallies["miscalibrated"]:
            return "miscalibrated", tallies
        if tallies["overconfident"] or tallies["underconfident"]:
            return "contested", tallies
        if tallies["not-assessed"]:
            return "partially-calibrated", tallies
        return "calibrated", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._uncertainties.get(record_id)
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
                _verify_payload(provisional), "ai-uncertainty.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, subject_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one subject's uncertainty posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            subject_id = _check_id(subject_id, "subject_id")
            if subject_id not in self._subject_uncertainties:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            posture, tallies = self._posture(subject_id)
            provisional = EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_quantifications=len(self._subject_uncertainties[subject_id]),
                n_well_calibrated=tallies["well-calibrated"],
                n_overconfident=tallies["overconfident"],
                n_underconfident=tallies["underconfident"],
                n_miscalibrated=tallies["miscalibrated"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=self._integrity_ok(subject_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-uncertainty.evaluate"
            )
            return EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_quantifications=len(self._subject_uncertainties[subject_id]),
                n_well_calibrated=tallies["well-calibrated"],
                n_overconfident=tallies["overconfident"],
                n_underconfident=tallies["underconfident"],
                n_miscalibrated=tallies["miscalibrated"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=self._integrity_ok(subject_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def uncertainty_record(self, uncertainty_id: str, seq: int) -> UncertaintyRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._uncertainties.get(uncertainty_id)
            if rec is None:
                raise UnknownUncertaintyError(
                    f"unknown uncertainty: {uncertainty_id!r}"
                )
            return rec

    def uncertainties_for(
        self, subject_id: str, seq: int
    ) -> Tuple[UncertaintyRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._uncertainties[uid]
                for uid in self._subject_uncertainties.get(subject_id, [])
            )

    def subject_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._subject_uncertainties.keys()))

    def uncertainty_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._uncertainties.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_subjects": len(self._subject_uncertainties),
                "n_uncertainties": len(self._uncertainties),
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
    """Self-check: exercise quantify -> verify -> evaluate -> retire."""
    ledger = AIUncertainty()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.quantify(
        "sub-1", 1, uncertainty_kind="conformal", verdict="well-calibrated",
        score=92,
    )
    assert rec.verify()
    rec2 = ledger.quantify(
        "sub-1", 2, uncertainty_kind="epistemic", verdict="not-assessed"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.uncertainty_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sub-1", 4)
    assert ev.posture == "partially-calibrated"
    ret = ledger.retire("sub-1", 5)
    assert ret.verify()
    print("ai-uncertainty OK: quantify, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
