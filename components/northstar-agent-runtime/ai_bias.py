"""AI bias: bias detection/mitigation decision ledger, Simulated.

Research note: AI bias covers systematic, repeatable errors in AI systems
that create unfair outcomes - skew in training data, annotation, modeling,
evaluation, or deployment. This module is the *decision ledger* for
declared AI-bias detections: which systems had which bias detections booked
(over a pinned bias-kind vocabulary), what verdicts were declared against
them, what mitigations the host declared, and what bias posture the ledger
derives - defensible bookkeeping, never proof that a system is really
unbiased.

This module owns the detect -> mitigate -> evaluate lifecycle:

* **detect()** - book one declared bias detection (minted ``det-N`` ids;
  pinned bias-kind vocabulary over the common AI-bias classes; pinned
  verdict vocabulary booked *as data*); the first detection registers its
  system; raw datasets, labels, predictions, and metrics never enter
  records - digest pins only.
* **mitigate()** - book one declared mitigation against a booked detection
  (minted ``mit-N`` ids; pinned mitigation-strategy vocabulary booked
  *as data*); repeatable chain; books the *declaration*, never the deployed
  fix.
* **verify()** - **pure read**: re-derive one detection/mitigation record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the detection really happened.
* **evaluate()** - **pure read**: derive one system's bias posture as data
  (``unevaluated`` -> ``bias-open`` -> ``uncertain`` -> ``mitigated`` ->
  ``clean``) with verdict tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``fairness_eval.py`` owns the
fairness *evaluation-run* lifecycle (declared eval runs and their declared
metrics); the sibling ``ai_fairness.py`` owns the fairness
*assessment/mitigation* lifecycle; this module is the bias *detection*
decision ledger none of them own: declared detections against the pinned
bias-kind taxonomy (representation, measurement, sampling, algorithmic,
annotation, evaluation, deployment), declared mitigations against those
detections, digest re-derivation, and the ledger-rule posture that turns
declared verdicts into a bias claim, always as data, never as measured
truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-bias.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no data, applies no
mitigations, and proves nothing about real AI bias. A booked
``bias-detected`` verdict means "the host declared it", never "the system
is biased"; a booked mitigation means "the host declared it", never "the
bias is gone". Datasets, labels, predictions, model weights, and raw
detection material never enter records or cross the audit boundary -
digest pins only.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_BIAS_VERSION = "ai-bias.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-bias.v1"

#: Pinned bias-kind vocabulary (the AI-bias classes detected).
BIAS_KINDS = (
    "representation-bias",
    "measurement-bias",
    "sampling-bias",
    "algorithmic-bias",
    "annotation-bias",
    "evaluation-bias",
    "deployment-bias",
    "interaction-bias",
)

#: Pinned detection-verdict vocabulary (booked as data, never proof).
DETECT_VERDICTS = (
    "bias-detected",
    "suspected",
    "inconclusive",
    "no-bias",
)

#: Pinned mitigation-strategy vocabulary (booked as data, never proof).
MITIGATION_STRATEGIES = (
    "reweighting",
    "resampling",
    "debias-constraints",
    "adversarial-debiasing",
    "data-augmentation",
    "postprocessing-calibration",
    "retraining",
    "no-action",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned evaluate-posture vocabulary (booked as data).
EVALUATE_POSTURES = (
    "unevaluated",
    "bias-open",
    "uncertain",
    "mitigated",
    "clean",
)

#: Pinned retire-reason vocabulary (declared data, emittable).
RETIRE_REASONS = (
    "manual",
    "decommissioned",
    "superseded",
    "policy",
)

#: Audit row schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit kinds this module may emit.
AUDIT_KINDS = (
    "detected",
    "mitigated",
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
        "dataset",
        "datasets",
        "labels",
        "label",
        "predictions",
        "prediction",
        "scores",
        "score",
        "metrics",
        "metric",
        "embedding",
        "embeddings",
        "features",
        "feature",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "transcript",
        "transcripts",
        "trace",
        "traces",
        "trajectory",
        "trajectories",
        "log",
        "logs",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "checkpoint_data",
        "activations",
        "gradients",
        "feedback",
        "annotations",
        "annotation",
        "demographic",
        "demographics",
        "user_data",
        "training_data",
        "eval_data",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIBiasError(Exception):
    """Base class for all ai-bias ledger errors."""


class BadSystemError(AIBiasError):
    pass


class UnknownSystemError(AIBiasError):
    pass


class RetiredSystemError(AIBiasError):
    pass


class BadBiasKindError(AIBiasError):
    pass


class BadVerdictError(AIBiasError):
    pass


class BadDigestError(AIBiasError):
    pass


class BadReasonError(AIBiasError):
    pass


class UnknownDetectionError(AIBiasError):
    pass


class UnknownMitigationError(AIBiasError):
    pass


class UnknownRecordError(AIBiasError):
    pass


class BadStrategyError(AIBiasError):
    pass


class SeqOrderError(AIBiasError):
    pass


class AuditKindError(AIBiasError):
    pass


# ---------------------------------------------------------------------------
# Canonical payloads / digest pins
# ---------------------------------------------------------------------------


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    if isinstance(raw, str):
        return raw.encode("utf-8")
    return raw


def _digest_pin(payload: Dict[str, Any], tag: str) -> str:
    body = {"schema": SCHEMA_PIN, "tag": tag, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _detect_payload(rec: "DetectionRecord") -> Dict[str, Any]:
    return {
        "detection_id": rec.detection_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "bias_kind": rec.bias_kind,
        "verdict": rec.verdict,
        "detection_digest": rec.detection_digest,
    }


def _mitigate_payload(rec: "MitigationRecord") -> Dict[str, Any]:
    return {
        "mitigation_id": rec.mitigation_id,
        "detection_id": rec.detection_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "mitigation_digest": rec.mitigation_digest,
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
        "n_detections": rep.n_detections,
        "n_bias_detected": rep.n_bias_detected,
        "n_suspected": rep.n_suspected,
        "n_inconclusive": rep.n_inconclusive,
        "n_no_bias": rep.n_no_bias,
        "n_mitigated": rep.n_mitigated,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    system_id: str
    seq: int
    bias_kind: str
    verdict: str
    detection_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_detect_payload(self), "ai-bias.detect")


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    detection_id: str
    system_id: str
    seq: int
    strategy: str
    mitigation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _mitigate_payload(self), "ai-bias.mitigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-bias.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_verify_payload(self), "ai-bias.verify")


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_detections: int
    n_bias_detected: int
    n_suspected: int
    n_inconclusive: int
    n_no_bias: int
    n_mitigated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-bias.evaluate"
        )


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadSystemError(f"{name} must be a non-empty str")
    return value


def _check_bias_kind(value: Any) -> str:
    if value not in BIAS_KINDS:
        raise BadBiasKindError(f"unknown bias_kind: {value!r}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in DETECT_VERDICTS:
        raise BadVerdictError(f"unknown verdict: {value!r}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in MITIGATION_STRATEGIES:
        raise BadStrategyError(f"unknown strategy: {value!r}")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be a str")
    if value and not value.startswith("sha256:"):
        raise BadDigestError(f"{name} must be '' or a 'sha256:' pin")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"unknown reason: {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


def ai_bias_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIBiasError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "module": "ai-bias",
        "version": AI_BIAS_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIBias:
    """AI-bias detection/mitigation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and mitigations
    are booked as data - never proof that a system is really unbiased.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._detections: Dict[str, DetectionRecord] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._system_detections: Dict[str, List[str]] = {}
        self._detection_mitigations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._detection_counter = 0
        self._mitigation_counter = 0
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
            row = ai_bias_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": AUDIT_SCHEMA,
                "module": "ai-bias",
                "version": AI_BIAS_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_bias_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def detect(
        self,
        system_id: str,
        seq: int,
        bias_kind: str = "representation-bias",
        verdict: str = "suspected",
        detection_digest: str = "",
    ) -> DetectionRecord:
        """Book one declared bias detection (minted ``det-N`` id).

        The first detection on an id registers the system. Raw datasets,
        labels, predictions, and metrics never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book an
        ``ai-bias.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                bias_kind = _check_bias_kind(bias_kind)
                verdict = _check_verdict(verdict)
                detection_digest = _check_digest(
                    detection_digest, "detection_digest"
                )
                self._require_live(system_id)
            except AIBiasError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._detection_counter += 1
            detection_id = f"det-{self._detection_counter}"
            provisional = DetectionRecord(
                detection_id=detection_id,
                system_id=system_id,
                seq=seq,
                bias_kind=bias_kind,
                verdict=verdict,
                detection_digest=detection_digest,
                digest="",
            )
            digest = _digest_pin(_detect_payload(provisional), "ai-bias.detect")
            rec = DetectionRecord(
                detection_id=detection_id,
                system_id=system_id,
                seq=seq,
                bias_kind=bias_kind,
                verdict=verdict,
                detection_digest=detection_digest,
                digest=digest,
            )
            self._detections[detection_id] = rec
            self._system_detections.setdefault(system_id, []).append(detection_id)
            self._detection_mitigations[detection_id] = []
            self._emit(
                "detected",
                seq,
                detection_id=detection_id,
                system_id=system_id,
                bias_kind=bias_kind,
                verdict=verdict,
            )
            return rec

    def mitigate(
        self,
        detection_id: str,
        seq: int,
        strategy: str = "no-action",
        mitigation_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation against a booked detection.

        Minted ``mit-N`` ids; repeatable chain; books the *declaration*,
        never the deployed fix. Fail-closed on unknown detections and
        retired systems.
        """
        with self._lock:
            try:
                detection_id = _check_id(detection_id, "detection_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                mitigation_digest = _check_digest(
                    mitigation_digest, "mitigation_digest"
                )
                det = self._detections.get(detection_id)
                if det is None:
                    raise UnknownDetectionError(
                        f"unknown detection: {detection_id!r}"
                    )
                self._require_live(det.system_id)
            except AIBiasError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._mitigation_counter += 1
            mitigation_id = f"mit-{self._mitigation_counter}"
            provisional = MitigationRecord(
                mitigation_id=mitigation_id,
                detection_id=detection_id,
                system_id=det.system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest="",
            )
            digest = _digest_pin(
                _mitigate_payload(provisional), "ai-bias.mitigate"
            )
            rec = MitigationRecord(
                mitigation_id=mitigation_id,
                detection_id=detection_id,
                system_id=det.system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest=digest,
            )
            self._mitigations[mitigation_id] = rec
            self._detection_mitigations[detection_id].append(mitigation_id)
            self._emit(
                "mitigated",
                seq,
                mitigation_id=mitigation_id,
                detection_id=detection_id,
                system_id=det.system_id,
                strategy=strategy,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Retire a system id; terminal, ids never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_detections:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
            except AIBiasError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-bias.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _read_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin.

        Verdict ``verified`` / ``tampered`` is booked as data, never as
        proof the record's content was true.
        """
        seq = self._read_seq(seq)
        with self._lock:
            rec = self._detections.get(record_id)
            if rec is None:
                rec = self._mitigations.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            if isinstance(rec, DetectionRecord):
                expected = _digest_pin(_detect_payload(rec), "ai-bias.detect")
            else:
                expected = _digest_pin(
                    _mitigate_payload(rec), "ai-bias.mitigate"
                )
            ok = rec.digest == expected
            verdict = "verified" if ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-bias.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's bias posture as data.

        ``unevaluated`` -> ``bias-open`` (any unmitigated
        ``bias-detected``) -> ``uncertain`` (any ``suspected`` /
        ``inconclusive``) -> ``mitigated`` (all ``bias-detected`` covered)
        -> ``clean`` (all ``no-bias``).
        """
        system_id = _check_id(system_id, "system_id")
        seq = self._read_seq(seq)
        with self._lock:
            det_ids = self._system_detections.get(system_id)
            if det_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            detections = [self._detections[d] for d in det_ids]
            n_bias = n_susp = n_incon = n_clean = 0
            n_mitig = 0
            any_open = False
            for det in detections:
                if det.verdict == "bias-detected":
                    n_bias += 1
                elif det.verdict == "suspected":
                    n_susp += 1
                elif det.verdict == "inconclusive":
                    n_incon += 1
                else:
                    n_clean += 1
                mitigations = self._detection_mitigations[det.detection_id]
                if mitigations:
                    n_mitig += 1
                elif det.verdict == "bias-detected":
                    any_open = True
            if not detections:
                posture = "unevaluated"
            elif any_open:
                posture = "bias-open"
            elif n_susp or n_incon:
                posture = "uncertain"
            elif n_bias and n_mitig == n_bias:
                posture = "mitigated"
            elif n_clean == len(detections):
                posture = "clean"
            else:
                posture = "mitigated"
            integrity_ok = all(
                d.digest == _digest_pin(_detect_payload(d), "ai-bias.detect")
                for d in detections
            ) and all(
                m.digest
                == _digest_pin(_mitigate_payload(m), "ai-bias.mitigate")
                for det in detections
                for m in (
                    self._mitigations[mid]
                    for mid in self._detection_mitigations[det.detection_id]
                )
            )
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_detections=len(detections),
                n_bias_detected=n_bias,
                n_suspected=n_susp,
                n_inconclusive=n_incon,
                n_no_bias=n_clean,
                n_mitigated=n_mitig,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-bias.evaluate"
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_detections=len(detections),
                n_bias_detected=n_bias,
                n_suspected=n_susp,
                n_inconclusive=n_incon,
                n_no_bias=n_clean,
                n_mitigated=n_mitig,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views ---------------------------------------------------

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        seq = self._read_seq(seq)
        with self._lock:
            rec = self._detections.get(detection_id)
            if rec is None:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}"
                )
            return rec

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        seq = self._read_seq(seq)
        with self._lock:
            rec = self._mitigations.get(mitigation_id)
            if rec is None:
                raise UnknownMitigationError(
                    f"unknown mitigation: {mitigation_id!r}"
                )
            return rec

    def detections_for(self, system_id: str, seq: int) -> List[DetectionRecord]:
        system_id = _check_id(system_id, "system_id")
        seq = self._read_seq(seq)
        with self._lock:
            det_ids = self._system_detections.get(system_id)
            if det_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return [self._detections[d] for d in det_ids]

    def mitigations_for(
        self, detection_id: str, seq: int
    ) -> List[MitigationRecord]:
        detection_id = _check_id(detection_id, "detection_id")
        seq = self._read_seq(seq)
        with self._lock:
            if detection_id not in self._detections:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}"
                )
            return [
                self._mitigations[m]
                for m in self._detection_mitigations[detection_id]
            ]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        seq = self._read_seq(seq)
        with self._lock:
            return tuple(sorted(self._system_detections))

    def detection_ids(self, seq: int) -> Tuple[str, ...]:
        seq = self._read_seq(seq)
        with self._lock:
            return tuple(sorted(self._detections))

    def mitigation_ids(self, seq: int) -> Tuple[str, ...]:
        seq = self._read_seq(seq)
        with self._lock:
            return tuple(sorted(self._mitigations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        seq = self._read_seq(seq)
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        seq = self._read_seq(seq)
        with self._lock:
            return {
                "seq": self._seq,
                "n_systems": len(self._system_detections),
                "n_detections": len(self._detections),
                "n_mitigations": len(self._mitigations),
                "n_retired": len(self._retired),
            }

    def audit_log(self, seq: int) -> List[Dict[str, Any]]:
        seq = self._read_seq(seq)
        with self._lock:
            return list(self._audit)


# ---------------------------------------------------------------------------
# stdlib-only self-check
# ---------------------------------------------------------------------------

_ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
    }
)


def stdlib_only() -> bool:
    """AST self-check: the module imports only stdlib (+ the
    ``canonical_json`` try/except fallback)."""
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_STDLIB:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            if node.module.split(".")[0] not in _ALLOWED_STDLIB | {"canonical_json"}:
                return False
    return True


def main() -> None:
    ledger = AIBias()
    det = ledger.detect(
        "sys-1", 1, bias_kind="sampling-bias", verdict="bias-detected"
    )
    assert det.verify()
    mit = ledger.mitigate(det.detection_id, 2, strategy="resampling")
    assert mit.verify()
    rep = ledger.evaluate("sys-1", 3)
    assert rep.posture == "mitigated"
    assert rep.verify()
    assert stdlib_only()
    print("ai-bias OK: detect, mitigate, verify, evaluate, pins, audit")


if __name__ == "__main__":
    main()
