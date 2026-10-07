"""Gradient hacking as a deterministic single-host decision ledger.

Research note: gradient hacking is the failure mode in which a model
with situational awareness of its own training process subtly sabotages
its gradient updates -- masking or zeroing gradients that would alter
its internals, steering the optimizer away from alignment pressure,
shaping the loss landscape to resist modification, or concealing
capabilities by manipulating gradient flow (Hubinger et al., "Risks
from Learned Optimization"; the mesa-optimization literature). The
safety loop around this risk is: run declared gradient-hacking probes,
book host-declared evaluations with pinned verdicts, and verify digest
pins on demand. This module is the bookkeeping layer for that loop. It
runs no training, inspects no gradients, measures no losses, and proves
nothing about a model's true training behavior.

Distinct-layer rationale: ``reward_hacking.py`` owns the generic
probe -> detect -> mitigate lifecycle across eight hack classes
(``gradient-hacking`` appears there only as a probe kind, never as a
lifecycle); ``mesa_optimization.py`` owns mesa-optimization detection
mechanics (inner goals, corrigibility probes). Per the additive sibling
pattern, this module is the gradient-*hacking*-specific decision ledger
none of them own: declared detection probes over pinned
gradient-sabotage mechanism kinds, host-declared evaluation verdicts
booked as data, and pure-read digest verification -- all booked as
data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``gradient-hacking.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``hack-confirmed`` verdict means "the host
declared gradient hacking on this detection", never that the model
sabotaged its training. ``verify()`` re-derives digest pins as data;
it never proves real-world training integrity. Gradients, losses,
weights, optimizer states, and raw model internals never enter records
or cross the audit boundary -- digest pins only.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version.
GRADIENT_HACKING_VERSION = "gradient-hacking.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.gradient-hacking.v1"

#: Pinned probe-kind vocabulary (declared gradient-sabotage mechanisms).
PROBE_KINDS = (
    "gradient-direction-anomaly",
    "gradient-masking",
    "loss-landscape-shaping",
    "optimizer-sabotage",
    "representation-preservation",
    "capability-concealment",
    "selective-gradient-flow",
    "training-awareness-signal",
)

#: Pinned evaluation-verdict vocabulary. Verdicts are booked as data.
EVALUATE_VERDICTS = (
    "hack-confirmed",
    "hack-refuted",
    "inconclusive",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Pinned report-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "unprobed",
    "hack-confirmed",
    "suspect",
    "inconclusive",
    "clean",
)

#: Pinned verify-report verdict vocabulary.
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Keys banned from audit details (raw training material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "gradient", "gradients", "loss", "losses", "weights", "parameters",
    "params", "optimizer", "momentum", "policy", "trajectory",
    "evidence", "payload", "raw", "secret", "scenario",
    "transcript", "prompt", "response", "content", "text",
    "description", "notes", "model", "model_weights",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class GradientHackingError(Exception):
    """Base error for gradient-hacking ledger misuse."""


class SeqOrderError(GradientHackingError):
    """Seq is not a strictly increasing positive int."""


class BadIdError(GradientHackingError):
    """Malformed model, detection, or evaluation id."""


class UnknownModelError(GradientHackingError):
    """Model not registered."""


class UnknownRecordError(GradientHackingError):
    """Detection or evaluation record not booked."""


class BadKindError(GradientHackingError):
    """Unknown gradient-hacking probe kind."""


class BadVerdictError(GradientHackingError):
    """Unknown evaluation verdict."""


class BadScoreError(GradientHackingError):
    """Confidence is not an int in [0, 100]."""


class BadDigestError(GradientHackingError):
    """Malformed sha256: digest pin."""


class BadReasonError(GradientHackingError):
    """Unknown retirement reason."""


class RetiredModelError(GradientHackingError):
    """Model id already retired; never recycled."""


class AlreadyEvaluatedError(GradientHackingError):
    """Detection already has a booked evaluation."""


class AuditKindError(GradientHackingError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(body: dict) -> str:
    # The in-repo jcs_sha256_hex returns bare hex; pin it explicitly.
    return "sha256:" + jcs_sha256_hex(body)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadDigestError("digest must be a sha256: pin or ''")
    if value:
        hexpart = value[7:]
        if any(c not in "0123456789abcdef" for c in hexpart):
            raise BadDigestError("digest hex must be lowercase hex")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


def _check_confidence(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("confidence must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadScoreError("confidence must be in [0, 100]")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionRecord:
    """One declared gradient-hacking detection probe for a model."""

    detection_id: str
    model_id: str
    probe_kind: str
    confidence: int
    probe_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "model_id": self.model_id,
            "probe_kind": self.probe_kind,
            "confidence": self.confidence,
            "probe_digest": self.probe_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class EvaluationRecord:
    """One host-declared evaluation verdict for a detection."""

    evaluation_id: str
    detection_id: str
    model_id: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "evaluation_id": self.evaluation_id,
            "detection_id": self.detection_id,
            "model_id": self.model_id,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RetireRecord:
    """One terminal model retirement."""

    model_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest verification result for one record (as data)."""

    record_id: str
    record_kind: str
    verdict: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "verdict": self.verdict,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class GradientHackingReport:
    """Derived gradient-hacking posture report (pure read)."""

    seq: int
    model_id: str
    n_models: int
    n_detections: int
    n_evaluations: int
    verdict_tallies: tuple
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "model_id": self.model_id,
            "n_models": self.n_models,
            "n_detections": self.n_detections,
            "n_evaluations": self.n_evaluations,
            "verdict_tallies": [list(p) for p in self.verdict_tallies],
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "detected",
    "evaluated",
    "retired",
    "gradient-hacking.rejected",
)


def gradient_hacking_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw training keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw training key banned from audit: {key!r}")
    return {"kind": "gradient-hacking." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class GradientHacking:
    """Gradient-hacking decision ledger: detect -> evaluate -> verify."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._detections: dict[str, DetectionRecord] = {}
        self._detection_ids: list[str] = []
        self._evaluations: dict[str, EvaluationRecord] = {}
        self._evaluation_ids: list[str] = []
        self._evaluated_detections: set[str] = set()
        self._retired: dict[str, RetireRecord] = {}
        self._audit: list[dict] = []
        self._n_rejected = 0

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(gradient_hacking_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("gradient-hacking.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def detect(self, model_id: str, seq: int,
               probe_kind: str = "gradient-direction-anomaly",
               confidence: int = 0,
               probe_digest: str = "") -> DetectionRecord:
        """Book one declared gradient-hacking probe (minted gdt-N).

        The first probe registers its model. Raw gradients, losses,
        weights, and optimizer states never enter records -- digest
        pins only. ``confidence`` is a host-reported int in [0, 100].
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if model_id in self._retired:
                    raise RetiredModelError(f"model id never recycled: {model_id!r}")
                if probe_kind not in PROBE_KINDS:
                    raise BadKindError(f"bad probe kind: {probe_kind!r}")
                _check_confidence(confidence)
                _check_digest(probe_digest)
                detection_id = f"gdt-{len(self._detection_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "detection_id": detection_id,
                    "model_id": model_id,
                    "probe_kind": probe_kind,
                    "confidence": confidence,
                    "probe_digest": probe_digest,
                    "seq": seq,
                }
                rec = DetectionRecord(
                    detection_id=detection_id,
                    model_id=model_id,
                    probe_kind=probe_kind,
                    confidence=confidence,
                    probe_digest=probe_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._detections[detection_id] = rec
                self._detection_ids.append(detection_id)
                self._emit("detected", {
                    "detection_id": detection_id,
                    "model_id": model_id,
                    "probe_kind": probe_kind,
                    "confidence": confidence,
                    "seq": seq,
                })
                return rec
            except GradientHackingError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def evaluate(self, detection_id: str, seq: int,
                 verdict: str = "inconclusive",
                 evidence_digest: str = "") -> EvaluationRecord:
        """Book one host-declared evaluation verdict (minted evl-N).

        The verdict is booked **as data**, never proof: a booked
        ``hack-confirmed`` means the host declared gradient hacking,
        never that the model sabotaged its training. Fail-closed: at
        most one evaluation per detection.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(detection_id)
                try:
                    det = self._detections[detection_id]
                except KeyError:
                    raise UnknownRecordError(f"unknown detection: {detection_id!r}")
                if det.model_id in self._retired:
                    raise RetiredModelError(
                        f"model already retired: {det.model_id!r}")
                if detection_id in self._evaluated_detections:
                    raise AlreadyEvaluatedError(
                        f"detection already evaluated: {detection_id!r}")
                if verdict not in EVALUATE_VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                _check_digest(evidence_digest)
                evaluation_id = f"evl-{len(self._evaluation_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "evaluation_id": evaluation_id,
                    "detection_id": detection_id,
                    "model_id": det.model_id,
                    "verdict": verdict,
                    "evidence_digest": evidence_digest,
                    "seq": seq,
                }
                rec = EvaluationRecord(
                    evaluation_id=evaluation_id,
                    detection_id=detection_id,
                    model_id=det.model_id,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._evaluations[evaluation_id] = rec
                self._evaluation_ids.append(evaluation_id)
                self._evaluated_detections.add(detection_id)
                self._emit("evaluated", {
                    "evaluation_id": evaluation_id,
                    "detection_id": detection_id,
                    "model_id": det.model_id,
                    "verdict": verdict,
                    "seq": seq,
                })
                return rec
            except GradientHackingError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def retire(self, model_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminally retire a model id; ids are never recycled.

        Post-retire ``detect`` / ``evaluate`` mutations are refused;
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if model_id in self._retired:
                    raise RetiredModelError(f"model already retired: {model_id!r}")
                if model_id not in self._known_models():
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                body = {
                    "schema": SCHEMA_PIN,
                    "model_id": model_id,
                    "reason": reason,
                    "seq": seq,
                }
                rec = RetireRecord(
                    model_id=model_id,
                    reason=reason,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._retired[model_id] = rec
                self._emit("retired", {
                    "model_id": model_id,
                    "reason": reason,
                    "seq": seq,
                })
                return rec
            except GradientHackingError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_models(self) -> set[str]:
        return {r.model_id for r in self._detections.values()} | \
               {r.model_id for r in self._evaluations.values()}

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._detections[detection_id]
            except KeyError:
                raise UnknownRecordError(f"unknown detection: {detection_id!r}")

    def evaluation_record(self, evaluation_id: str, seq: int) -> EvaluationRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._evaluations[evaluation_id]
            except KeyError:
                raise UnknownRecordError(f"unknown evaluation: {evaluation_id!r}")

    def detections_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(d for d in self._detection_ids
                         if self._detections[d].model_id == model_id)

    def evaluations_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(e for e in self._evaluation_ids
                         if self._evaluations[e].model_id == model_id)

    def model_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_models()))

    def retired_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Re-derive a record's digest pin and report the verdict as data.

        Pure read: seq is validated but never consumed and no audit row
        is emitted. ``verified`` means the pin matches; ``tampered``
        means the stored digest no longer matches the record body.
        """
        with self._lock:
            self._view_seq(seq)
            _check_id(record_id)
            if record_id in self._detections:
                rec = self._detections[record_id]
                record_kind = "detection"
            elif record_id in self._evaluations:
                rec = self._evaluations[record_id]
                record_kind = "evaluation"
            else:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            body = {
                "schema": SCHEMA_PIN,
                "record_id": record_id,
                "record_kind": record_kind,
                "verdict": verdict,
                "seq": seq,
            }
            return VerificationReport(
                record_id=record_id,
                record_kind=record_kind,
                verdict=verdict,
                seq=seq,
                digest=_record_digest(body),
            )

    def report(self, seq: int, model_id: str = "") -> GradientHackingReport:
        """Derive a gradient-hacking posture report (pure read).

        ``model_id`` scopes to one model with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never
        proof of real-world training integrity:

        - ``unprobed``: no detections and no evaluations in scope
        - ``hack-confirmed``: any evaluation verdict ``hack-confirmed``
        - ``suspect``: any detection without a booked evaluation
          (unevaluated detections stay suspect, fail-closed)
        - ``inconclusive``: any evaluation verdict ``inconclusive``
        - ``clean``: otherwise (every detection evaluated, all refuted)
        """
        with self._lock:
            self._view_seq(seq)
            if model_id:
                _check_id(model_id)
                if model_id not in self._known_models():
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                dids = self.detections_for(model_id, seq)
                eids = self.evaluations_for(model_id, seq)
                n_models = 1
            else:
                dids = tuple(self._detection_ids)
                eids = tuple(self._evaluation_ids)
                n_models = len(self._known_models())
            tallies: dict[str, int] = {}
            for eid in eids:
                v = self._evaluations[eid].verdict
                tallies[v] = tallies.get(v, 0) + 1
            unevaluated = [d for d in dids
                           if d not in self._evaluated_detections]
            if not dids and not eids:
                posture = "unprobed"
            elif tallies.get("hack-confirmed", 0) > 0:
                posture = "hack-confirmed"
            elif unevaluated:
                posture = "suspect"
            elif tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
            else:
                posture = "clean"
            verdict_tallies = tuple(sorted(tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "model_id": model_id,
                "n_models": n_models,
                "n_detections": len(dids),
                "n_evaluations": len(eids),
                "verdict_tallies": [list(p) for p in verdict_tallies],
                "posture": posture,
            }
            return GradientHackingReport(
                seq=seq,
                model_id=model_id,
                n_models=n_models,
                n_detections=len(dids),
                n_evaluations=len(eids),
                verdict_tallies=verdict_tallies,
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "models": len(self._known_models()),
                "detections": len(self._detections),
                "evaluations": len(self._evaluations),
                "retired": len(self._retired),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    gh = GradientHacking()
    d = gh.detect("m1", 1, probe_kind="gradient-masking", confidence=64,
                 probe_digest="sha256:" + "a" * 64)
    assert d.verify() and d.detection_id == "gdt-1"
    e = gh.evaluate("gdt-1", 2, verdict="hack-confirmed")
    assert e.verify() and e.evaluation_id == "evl-1"
    v = gh.verify("gdt-1", 3)
    assert v.verify() and v.verdict == "verified"
    rep = gh.report(4, "m1")
    assert rep.verify() and rep.posture == "hack-confirmed"
    assert rep.n_detections == 1 and rep.n_evaluations == 1
    gh.retire("m1", 5, reason="decommissioned")
    assert gh.stats(6)["retired"] == 1
    print("gradient-hacking OK: detect, evaluate, verify, report, retire, pins, audit")


if __name__ == "__main__":
    main()
