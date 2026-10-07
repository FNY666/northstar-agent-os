"""Systemic-risk governance as a deterministic single-host decision ledger.

Research note: the EU AI Act (Art. 55) treats general-purpose AI models
trained with more than ``10^25`` floating-point operations as carrying
``high-impact capabilities`` and therefore *systemic risk*: the harms at
stake are not per-deployment incidents but society-scale effects --
CBRN uplift, cyber-offense uplift, autonomous replication,
loss-of-control, large-scale persuasion, critical-infrastructure
disruption, discrimination at scale, and concentration of power. The
Act's prescribed loop is: classify the model by compute, evaluate it
against the systemic-risk vectors, *declare* mitigation measures, and
report. This module is the bookkeeping layer for that loop: it books
declared model registrations (with a pinned FLOPs class), host-declared
assessment verdicts, and declared mitigation decisions. It runs no
evaluations, measures no capabilities, books no real FLOPs, and proves
nothing about real systemic danger.

Distinct-layer rationale: ``grc.py`` owns the generic governance
workflow (register framework / assess finding / remediate / certify),
``compliance.py`` owns per-framework control checks, ``gpai.py`` owns
the GPAI classification record, and ``ai_act.py`` owns the AI Act
conformity ledger. Per the additive sibling pattern, this module is the
systemic-risk *evaluation* layer none of them own: compute-classed
model registration, vector-level assessment verdicts (booked as data),
declared mitigation measures, and a derived reporting posture.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``systemic-risk.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only + ``canonical_json``
try/except fallback, ``sha256:`` digest pins with ``verify()``,
``audit.ndjson/1`` events.

Honest scope: a booked ``systemic`` verdict means "the host declared
this vector systemic", never that the model poses systemic risk. A
booked ``red-team-eval`` means "the host declared a red-team measure",
never that an evaluation happened. ``report()`` derives posture from
the ledger; it never proves real-world safety.
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
SYSTEMIC_RISK_VERSION = "systemic-risk.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.systemic-risk.v1"

#: Pinned compute-class vocabulary (EU AI Act Art. 55 ~10^25 FLOPs rule).
FLOPS_CLASSES = (
    "below-1e24",
    "1e24-to-1e25",
    "above-1e25",
)

#: Pinned systemic-risk vector vocabulary (Art. 55-style harm classes).
RISK_VECTORS = (
    "cbrn-uplift",
    "cyber-offense-uplift",
    "autonomous-replication",
    "loss-of-control",
    "large-scale-persuasion",
    "critical-infrastructure",
    "discrimination-at-scale",
    "power-concentration",
)

#: Pinned assessment-verdict vocabulary. Verdicts are booked as data.
ASSESS_VERDICTS = (
    "systemic",
    "elevated",
    "limited",
    "minimal",
)

#: Pinned mitigation-measure vocabulary (declared measures, not evidence).
MITIGATION_MEASURES = (
    "red-team-eval",
    "capability-restriction",
    "staged-deployment",
    "monitoring-plan",
    "incident-reporting",
    "security-hardening",
    "access-controls",
    "rollback-plan",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "model-withdrawn",
    "superseded",
    "decommissioned",
)

#: Pinned report-posture vocabulary (derived from the ledger, never proof).
POSTURES = (
    "not-assessed",
    "systemic-confirmed",
    "elevated",
    "limited",
    "minimal",
)

#: Keys banned from audit details (raw model material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "model",
    "weights", "checkpoint", "training", "data",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class SystemicRiskError(Exception):
    """Base error for systemic-risk misuse."""


class SeqOrderError(SystemicRiskError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(SystemicRiskError):
    """Raised on a malformed model, assessment, or mitigation id."""


class DuplicateModelError(SystemicRiskError):
    """Raised when a model id is already registered."""


class UnknownModelError(SystemicRiskError):
    """Raised when a model id is not registered."""


class RetiredModelError(SystemicRiskError):
    """Raised when mutating a retired model (ids never recycled)."""


class BadFlopsError(SystemicRiskError):
    """Raised on a compute class outside the pinned vocabulary."""


class BadVectorError(SystemicRiskError):
    """Raised on a risk vector outside the pinned vocabulary."""


class BadVerdictError(SystemicRiskError):
    """Raised on an assessment verdict outside the pinned vocabulary."""


class BadMeasureError(SystemicRiskError):
    """Raised on a mitigation measure outside the pinned vocabulary."""


class BadScoreError(SystemicRiskError):
    """Raised on a score outside int [0, 100] (bool refused)."""


class BadDigestError(SystemicRiskError):
    """Raised on a malformed sha256: digest pin."""


class BadReasonError(SystemicRiskError):
    """Raised on a retirement reason outside the pinned vocabulary."""


class AuditKindError(SystemicRiskError):
    """Raised on an unknown audit kind or a banned audit key."""


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
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


def _check_score(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError("score must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadScoreError("score must be in [0, 100]")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModelRecord:
    """One model registered under a pinned compute class."""

    model_id: str
    flops_class: str
    provider: str
    model_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "flops_class": self.flops_class,
            "provider": self.provider,
            "model_digest": self.model_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared systemic-risk assessment of a registered model."""

    assessment_id: str
    model_id: str
    risk_vector: str
    verdict: str
    score: int
    assessment_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "model_id": self.model_id,
            "risk_vector": self.risk_vector,
            "verdict": self.verdict,
            "score": self.score,
            "assessment_digest": self.assessment_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class MitigationRecord:
    """One declared systemic-risk mitigation measure for a model."""

    mitigation_id: str
    model_id: str
    measure: str
    plan_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "model_id": self.model_id,
            "measure": self.measure,
            "plan_digest": self.plan_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a model id (never recycled)."""

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
class SystemicRiskReport:
    """Derived systemic-risk posture report (pure read)."""

    seq: int
    model_id: str
    n_models: int
    n_assessments: int
    n_mitigations: int
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
            "n_assessments": self.n_assessments,
            "n_mitigations": self.n_mitigations,
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
    "registered",
    "assessed",
    "mitigated",
    "retired",
    "systemic-risk.rejected",
)


def systemic_risk_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw model keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw model key banned from audit: {key!r}")
    return {"kind": "systemic-risk." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class SystemicRisk:
    """Systemic-risk governance ledger: register -> assess -> mitigate -> report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._models: dict[str, ModelRecord] = {}
        self._retired: set[str] = set()
        self._assessments: dict[str, AssessmentRecord] = {}
        self._assessment_ids: list[str] = []
        self._mitigations: dict[str, MitigationRecord] = {}
        self._mitigation_ids: list[str] = []
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
        self._audit.append(systemic_risk_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("systemic-risk.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def register_model(self, model_id: str, seq: int,
                       flops_class: str = "below-1e24",
                       provider: str = "",
                       model_digest: str = "") -> ModelRecord:
        """Register one model under a pinned compute class.

        Retired ids are never recycled: the retired check precedes the
        duplicate check so retired ids report ``RetiredModelError``.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id in self._models:
                    raise DuplicateModelError(f"duplicate model: {model_id!r}")
                if flops_class not in FLOPS_CLASSES:
                    raise BadFlopsError(f"bad compute class: {flops_class!r}")
                if not isinstance(provider, str) or len(provider) > 128:
                    raise BadIdError("provider must be a str of <= 128 chars")
                _check_digest(model_digest)
                body = {
                    "schema": SCHEMA_PIN,
                    "model_id": model_id,
                    "flops_class": flops_class,
                    "provider": provider,
                    "model_digest": model_digest,
                    "seq": seq,
                }
                rec = ModelRecord(
                    model_id=model_id,
                    flops_class=flops_class,
                    provider=provider,
                    model_digest=model_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._models[model_id] = rec
                self._emit("registered", {
                    "model_id": model_id,
                    "flops_class": flops_class,
                    "seq": seq,
                })
                return rec
            except SystemicRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def assess(self, model_id: str, seq: int,
               risk_vector: str = "loss-of-control",
               verdict: str = "minimal",
               score: int = 0,
               assessment_digest: str = "") -> AssessmentRecord:
        """Book one declared systemic-risk assessment (minted asmt-N).

        The verdict is booked *as data*: a ``systemic`` verdict means
        the host declared systemic risk, never that the model poses it.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if risk_vector not in RISK_VECTORS:
                    raise BadVectorError(f"bad risk vector: {risk_vector!r}")
                if verdict not in ASSESS_VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                _check_score(score)
                _check_digest(assessment_digest)
                assessment_id = f"asmt-{len(self._assessment_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "assessment_id": assessment_id,
                    "model_id": model_id,
                    "risk_vector": risk_vector,
                    "verdict": verdict,
                    "score": score,
                    "assessment_digest": assessment_digest,
                    "seq": seq,
                }
                rec = AssessmentRecord(
                    assessment_id=assessment_id,
                    model_id=model_id,
                    risk_vector=risk_vector,
                    verdict=verdict,
                    score=score,
                    assessment_digest=assessment_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._assessments[assessment_id] = rec
                self._assessment_ids.append(assessment_id)
                self._emit("assessed", {
                    "assessment_id": assessment_id,
                    "model_id": model_id,
                    "risk_vector": risk_vector,
                    "verdict": verdict,
                    "score": score,
                    "seq": seq,
                })
                return rec
            except SystemicRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def mitigate(self, model_id: str, seq: int,
                 measure: str = "monitoring-plan",
                 plan_digest: str = "") -> MitigationRecord:
        """Book one declared mitigation measure (minted mit-N).

        Books the *declaration*, never the execution.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if measure not in MITIGATION_MEASURES:
                    raise BadMeasureError(f"bad measure: {measure!r}")
                _check_digest(plan_digest)
                mitigation_id = f"mit-{len(self._mitigation_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "mitigation_id": mitigation_id,
                    "model_id": model_id,
                    "measure": measure,
                    "plan_digest": plan_digest,
                    "seq": seq,
                }
                rec = MitigationRecord(
                    mitigation_id=mitigation_id,
                    model_id=model_id,
                    measure=measure,
                    plan_digest=plan_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._mitigations[mitigation_id] = rec
                self._mitigation_ids.append(mitigation_id)
                self._emit("mitigated", {
                    "mitigation_id": mitigation_id,
                    "model_id": model_id,
                    "measure": measure,
                    "seq": seq,
                })
                return rec
            except SystemicRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def retire(self, model_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminally retire a model id (never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id not in self._models:
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
                self._retired.add(model_id)
                self._emit("retired", {
                    "model_id": model_id,
                    "reason": reason,
                    "seq": seq,
                })
                return rec
            except SystemicRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def model_record(self, model_id: str, seq: int) -> ModelRecord:
        with self._lock:
            self._view_seq(seq)
            _check_id(model_id)
            try:
                return self._models[model_id]
            except KeyError:
                raise UnknownModelError(f"unknown model: {model_id!r}")

    def model_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._models)

    def is_retired(self, model_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq(seq)
            _check_id(model_id)
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return model_id in self._retired

    def retired_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._retired))

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._assessments[assessment_id]
            except KeyError:
                raise UnknownModelError(
                    f"unknown assessment: {assessment_id!r}")

    def assessments_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(a for a in self._assessment_ids
                         if self._assessments[a].model_id == model_id)

    def mitigations_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(m for m in self._mitigation_ids
                         if self._mitigations[m].model_id == model_id)

    def report(self, seq: int, model_id: str = "") -> SystemicRiskReport:
        """Derive a systemic-risk posture report (pure read).

        ``model_id`` scopes to one registered model; ``""`` aggregates
        the whole ledger. Verdicts are ledger truth, never proof.
        """
        with self._lock:
            self._view_seq(seq)
            if model_id:
                _check_id(model_id)
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                ids = self.assessments_for(model_id, seq)
                mids = self.mitigations_for(model_id, seq)
                n_models = 1
            else:
                ids = tuple(self._assessment_ids)
                mids = tuple(self._mitigation_ids)
                n_models = len(self._models)
            tallies: dict[str, int] = {}
            for aid in ids:
                v = self._assessments[aid].verdict
                tallies[v] = tallies.get(v, 0) + 1
            if not ids:
                posture = "not-assessed"
            elif tallies.get("systemic", 0) > 0:
                posture = "systemic-confirmed"
            elif tallies.get("elevated", 0) > 0:
                posture = "elevated"
            elif tallies.get("limited", 0) > 0:
                posture = "limited"
            else:
                posture = "minimal"
            verdict_tallies = tuple(sorted(tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "model_id": model_id,
                "n_models": n_models,
                "n_assessments": len(ids),
                "n_mitigations": len(mids),
                "verdict_tallies": [list(p) for p in verdict_tallies],
                "posture": posture,
            }
            return SystemicRiskReport(
                seq=seq,
                model_id=model_id,
                n_models=n_models,
                n_assessments=len(ids),
                n_mitigations=len(mids),
                verdict_tallies=verdict_tallies,
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "models": len(self._models),
                "retired": len(self._retired),
                "assessments": len(self._assessments),
                "mitigations": len(self._mitigations),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    sr = SystemicRisk()
    m = sr.register_model("gpt-next", 1, flops_class="above-1e25",
                          provider="example-lab",
                          model_digest="sha256:" + "a" * 64)
    assert m.verify() and m.flops_class == "above-1e25"
    a = sr.assess("gpt-next", 2, risk_vector="loss-of-control",
                  verdict="elevated", score=65)
    assert a.verify() and a.assessment_id == "asmt-1"
    mt = sr.mitigate("gpt-next", 3, measure="red-team-eval")
    assert mt.verify() and mt.mitigation_id == "mit-1"
    rep = sr.report(4)
    assert rep.verify() and rep.posture == "elevated"
    assert rep.n_models == 1 and rep.n_assessments == 1
    print("systemic-risk OK: register, assess, mitigate, report, pins, audit")


if __name__ == "__main__":
    main()
