"""Enterprise risk register governance as a deterministic single-host decision ledger.

Research note: enterprise risk management (ISO 31000, COSO ERM) runs a
governance cycle that is distinct from scoring a single risk: risks are
registered in a central register with an inherent likelihood x impact
rating, a treatment strategy is *decided* (avoid / reduce / transfer /
accept) with a named owner, and the register is reviewed on a cadence
until each risk is closed. This module is the bookkeeping layer for
that cycle: it books declared registrations, host-declared treatment
decisions, and declared periodic reviews. It performs no assessment
math beyond the booked 1-5 rating arithmetic, runs no monitoring
probes, and proves nothing about real exposure.

Distinct-layer rationale: ``risk_assessment.py`` owns the per-risk
assessment workflow (identify / score / mitigate as an assessment
exercise). This module owns the *governance* layer neither sibling
owns: the treatment-decision register (who decided what strategy for
which risk, and what residual rating they declared) plus the
periodic review chain that keeps the register alive until closure.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``risk-management.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only + ``canonical_json``
try/except fallback, ``sha256:`` digest pins with ``verify()``,
``audit.ndjson/1`` events.

Honest scope: a booked rating or strategy is host-reported data. A
booked ``reduce`` means "the host declared a reduce strategy", never
that exposure actually fell. ``monitor()`` books declared review
outcomes; a ``closed`` outcome means the host declared the risk closed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex, jcs_dumps  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def jcs_dumps(obj) -> str:  # noqa: D103
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


#: Module version.
RISK_MANAGEMENT_VERSION = "risk-management.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.risk-management.v1"

_HASH_DOMAIN = b"northstar.risk-management.v1\x00"

#: Pinned risk-category vocabulary (COSO / ISO 31000 style taxonomy).
RISK_CATEGORIES = (
    "strategic",
    "operational",
    "financial",
    "compliance",
    "reputational",
    "technology",
    "third-party",
    "environmental",
)

#: Pinned treatment-strategy vocabulary (ISO 31000 risk treatment).
TREATMENT_STRATEGIES = (
    "avoid",
    "reduce",
    "transfer",
    "accept",
)

#: Pinned review-outcome vocabulary for the monitoring chain.
REVIEW_OUTCOMES = (
    "improving",
    "stable",
    "deteriorating",
    "closed",
)

#: Keys banned from audit details (raw risk descriptions must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "detail", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "assessment",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class RiskManagementError(Exception):
    """Base error for risk-management misuse."""


class SeqOrderError(RiskManagementError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(RiskManagementError):
    """Raised on a malformed risk, treatment, or review id."""


class DuplicateRiskError(RiskManagementError):
    """Raised when a risk id is already registered."""


class UnknownRiskError(RiskManagementError):
    """Raised when a risk id is not in the register."""


class BadCategoryError(RiskManagementError):
    """Raised on a category outside the pinned vocabulary."""


class BadRatingError(RiskManagementError):
    """Raised on a likelihood/impact outside int [1, 5] (bool refused)."""


class BadDigestError(RiskManagementError):
    """Raised on a malformed sha256: digest pin."""


class BadStrategyError(RiskManagementError):
    """Raised on a treatment strategy outside the pinned vocabulary."""


class BadOwnerError(RiskManagementError):
    """Raised on a malformed treatment owner id."""


class BadOutcomeError(RiskManagementError):
    """Raised on a review outcome outside the pinned vocabulary."""


class ClosedRiskError(RiskManagementError):
    """Raised when mutating a risk the host already declared closed."""


class AuditKindError(RiskManagementError):
    """Raised on an unknown audit kind or a banned audit key."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(record_dict: dict) -> str:
    return "sha256:" + jcs_sha256_hex(record_dict)


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


def _check_rating(value: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRatingError(f"{what} must be an int in [1, 5]")
    if not 1 <= value <= 5:
        raise BadRatingError(f"{what} must be in [1, 5]")
    return value


def _rating_band(score: int) -> str:
    if score <= 4:
        return "low"
    if score <= 9:
        return "medium"
    if score <= 15:
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RiskRecord:
    """One risk registered in the register (inherent rating booked as data)."""

    risk_id: str
    category: str
    description_digest: str
    likelihood: int
    impact: int
    rating: int
    band: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "risk_id": self.risk_id,
            "category": self.category,
            "description_digest": self.description_digest,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "rating": self.rating,
            "band": self.band,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class TreatmentRecord:
    """One declared treatment decision for a registered risk."""

    treatment_id: str
    risk_id: str
    strategy: str
    owner: str
    residual_likelihood: int
    residual_impact: int
    residual_rating: int
    residual_band: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "treatment_id": self.treatment_id,
            "risk_id": self.risk_id,
            "strategy": self.strategy,
            "owner": self.owner,
            "residual_likelihood": self.residual_likelihood,
            "residual_impact": self.residual_impact,
            "residual_rating": self.residual_rating,
            "residual_band": self.residual_band,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class ReviewRecord:
    """One declared periodic review of a registered risk."""

    review_id: str
    risk_id: str
    outcome: str
    review_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "review_id": self.review_id,
            "risk_id": self.risk_id,
            "outcome": self.outcome,
            "review_digest": self.review_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RiskSummary:
    """Aggregate register posture (pure read)."""

    seq: int
    risks: int
    by_category: tuple
    by_band: tuple
    treatments: int
    reviews: int
    closed: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "risks": self.risks,
            "by_category": [list(p) for p in self.by_category],
            "by_band": [list(p) for p in self.by_band],
            "treatments": self.treatments,
            "reviews": self.reviews,
            "closed": self.closed,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("identified", "treated", "reviewed", "risk-management.rejected")


def risk_management_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw risk keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw risk key banned from audit: {key!r}")
    return {"kind": "risk-management." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class RiskManagement:
    """Risk register governance ledger: identify -> treat -> monitor."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._risks: dict[str, RiskRecord] = {}
        self._treatments: dict[str, TreatmentRecord] = {}
        self._treatment_ids: list[str] = []
        self._reviews: dict[str, ReviewRecord] = {}
        self._review_ids: list[str] = []
        self._closed: set[str] = set()
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
        self._audit.append(risk_management_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("risk-management.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def identify(self, risk_id: str, category: str, seq: int,
                 description_digest: str = "",
                 likelihood: int = 1, impact: int = 1) -> RiskRecord:
        """Register one risk. Raw descriptions never enter records."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(risk_id)
                if risk_id in self._risks:
                    raise DuplicateRiskError(f"duplicate risk: {risk_id!r}")
                if category not in RISK_CATEGORIES:
                    raise BadCategoryError(f"bad category: {category!r}")
                _check_digest(description_digest)
                _check_rating(likelihood, "likelihood")
                _check_rating(impact, "impact")
                rating = likelihood * impact
                band = _rating_band(rating)
                body = {
                    "schema": SCHEMA_PIN,
                    "risk_id": risk_id,
                    "category": category,
                    "description_digest": description_digest,
                    "likelihood": likelihood,
                    "impact": impact,
                    "rating": rating,
                    "band": band,
                    "seq": seq,
                }
                rec = RiskRecord(
                    risk_id=risk_id,
                    category=category,
                    description_digest=description_digest,
                    likelihood=likelihood,
                    impact=impact,
                    rating=rating,
                    band=band,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._risks[risk_id] = rec
                self._emit("identified", {
                    "risk_id": risk_id,
                    "category": category,
                    "rating": rating,
                    "band": band,
                    "seq": seq,
                })
                return rec
            except RiskManagementError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def treat(self, risk_id: str, strategy: str, seq: int,
              owner: str = "", residual_likelihood: int = 1,
              residual_impact: int = 1) -> TreatmentRecord:
        """Book one declared treatment decision (ISO 31000 vocabulary)."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(risk_id)
                if risk_id not in self._risks:
                    raise UnknownRiskError(f"unknown risk: {risk_id!r}")
                if risk_id in self._closed:
                    raise ClosedRiskError(f"risk is closed: {risk_id!r}")
                if strategy not in TREATMENT_STRATEGIES:
                    raise BadStrategyError(f"bad strategy: {strategy!r}")
                if not isinstance(owner, str) or len(owner) > 128:
                    raise BadOwnerError("owner must be a str of <= 128 chars")
                _check_rating(residual_likelihood, "residual_likelihood")
                _check_rating(residual_impact, "residual_impact")
                residual_rating = residual_likelihood * residual_impact
                residual_band = _rating_band(residual_rating)
                treatment_id = f"trt-{len(self._treatment_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "treatment_id": treatment_id,
                    "risk_id": risk_id,
                    "strategy": strategy,
                    "owner": owner,
                    "residual_likelihood": residual_likelihood,
                    "residual_impact": residual_impact,
                    "residual_rating": residual_rating,
                    "residual_band": residual_band,
                    "seq": seq,
                }
                rec = TreatmentRecord(
                    treatment_id=treatment_id,
                    risk_id=risk_id,
                    strategy=strategy,
                    owner=owner,
                    residual_likelihood=residual_likelihood,
                    residual_impact=residual_impact,
                    residual_rating=residual_rating,
                    residual_band=residual_band,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._treatments[treatment_id] = rec
                self._treatment_ids.append(treatment_id)
                self._emit("treated", {
                    "treatment_id": treatment_id,
                    "risk_id": risk_id,
                    "strategy": strategy,
                    "owner": owner,
                    "residual_rating": residual_rating,
                    "residual_band": residual_band,
                    "seq": seq,
                })
                return rec
            except RiskManagementError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def monitor(self, risk_id: str, seq: int, outcome: str = "stable",
                review_digest: str = "") -> ReviewRecord:
        """Book one declared periodic review. ``closed`` is terminal."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(risk_id)
                if risk_id not in self._risks:
                    raise UnknownRiskError(f"unknown risk: {risk_id!r}")
                if risk_id in self._closed:
                    raise ClosedRiskError(f"risk is closed: {risk_id!r}")
                if outcome not in REVIEW_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                _check_digest(review_digest)
                review_id = f"rvw-{len(self._review_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "review_id": review_id,
                    "risk_id": risk_id,
                    "outcome": outcome,
                    "review_digest": review_digest,
                    "seq": seq,
                }
                rec = ReviewRecord(
                    review_id=review_id,
                    risk_id=risk_id,
                    outcome=outcome,
                    review_digest=review_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._reviews[review_id] = rec
                self._review_ids.append(review_id)
                if outcome == "closed":
                    self._closed.add(risk_id)
                self._emit("reviewed", {
                    "review_id": review_id,
                    "risk_id": risk_id,
                    "outcome": outcome,
                    "seq": seq,
                })
                return rec
            except RiskManagementError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def risk(self, risk_id: str, seq: int) -> RiskRecord:
        with self._lock:
            self._view_seq(seq)
            _check_id(risk_id)
            try:
                return self._risks[risk_id]
            except KeyError:
                raise UnknownRiskError(f"unknown risk: {risk_id!r}")

    def risk_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._risks)

    def is_closed(self, risk_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq(seq)
            _check_id(risk_id)
            if risk_id not in self._risks:
                raise UnknownRiskError(f"unknown risk: {risk_id!r}")
            return risk_id in self._closed

    def treatment(self, treatment_id: str, seq: int) -> TreatmentRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._treatments[treatment_id]
            except KeyError:
                raise UnknownRiskError(f"unknown treatment: {treatment_id!r}")

    def treatments_for(self, risk_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(t for t in self._treatment_ids
                         if self._treatments[t].risk_id == risk_id)

    def reviews_for(self, risk_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(r for r in self._review_ids
                         if self._reviews[r].risk_id == risk_id)

    def latest_treatment(self, risk_id: str, seq: int):
        """Newest booked treatment for a risk, or None."""
        with self._lock:
            self._view_seq(seq)
            tids = self.treatments_for(risk_id, seq)
            return self._treatments[tids[-1]] if tids else None

    def latest_review(self, risk_id: str, seq: int):
        """Newest booked review for a risk, or None."""
        with self._lock:
            self._view_seq(seq)
            rids = self.reviews_for(risk_id, seq)
            return self._reviews[rids[-1]] if rids else None

    def summary(self, seq: int) -> RiskSummary:
        """Aggregate register posture (pure read)."""
        with self._lock:
            self._view_seq(seq)
            by_category: dict[str, int] = {}
            by_band: dict[str, int] = {}
            for rec in self._risks.values():
                by_category[rec.category] = by_category.get(rec.category, 0) + 1
                by_band[rec.band] = by_band.get(rec.band, 0) + 1
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "risks": len(self._risks),
                "by_category": sorted(by_category.items()),
                "by_band": sorted(by_band.items()),
                "treatments": len(self._treatments),
                "reviews": len(self._reviews),
                "closed": len(self._closed),
            }
            return RiskSummary(
                seq=seq,
                risks=len(self._risks),
                by_category=tuple(sorted(by_category.items())),
                by_band=tuple(sorted(by_band.items())),
                treatments=len(self._treatments),
                reviews=len(self._reviews),
                closed=len(self._closed),
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "risks": len(self._risks),
                "treatments": len(self._treatments),
                "reviews": len(self._reviews),
                "closed": len(self._closed),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    rm = RiskManagement()
    rec = rm.identify("risk-1", "technology", 1,
                      description_digest="sha256:" + "a" * 64,
                      likelihood=4, impact=5)
    assert rec.verify() and rec.rating == 20 and rec.band == "critical"
    trt = rm.treat("risk-1", "reduce", 2, owner="sec-team",
                   residual_likelihood=2, residual_impact=3)
    assert trt.verify() and trt.treatment_id == "trt-1"
    rvw = rm.monitor("risk-1", 3, outcome="improving")
    assert rvw.verify() and rvw.review_id == "rvw-1"
    summ = rm.summary(4)
    assert summ.verify() and summ.risks == 1 and summ.closed == 0
    print("risk-management OK: identify, treat, monitor, summary, pins, audit")


if __name__ == "__main__":
    main()
