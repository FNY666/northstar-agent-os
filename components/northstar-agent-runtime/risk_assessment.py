"""RiskAssessment: risk identification / scoring / mitigation bookkeeping for agents.

Research note: risk management (NIST SP 800-30 "Guide for Conducting Risk
Assessments"; ISO 31000:2018) decomposes assessment into risk
*identification* (naming hazards), *analysis* (likelihood x impact), and
*risk treatment* (avoid / reduce / transfer / accept). This module is the
*ledger* layer for that practice:

* **identify()** books one declared risk against a pinned category
  vocabulary (operational / technical / security / privacy / safety /
  compliance / reputational / financial); the risk title and description
  are pinned by digest only and never enter records. Risk ids are minted
  (``risk-N``).
* **score()** books one declared scoring of a booked risk: host-reported
  likelihood and impact in [0,1] (GIGO), with the risk score derived by
  exact integer arithmetic as ``likelihood x impact`` booked as reduced
  ``num/den`` fraction text (no floats), and a pinned rating (low /
  moderate / high / critical) derived from pinned thresholds. Verdicts
  are data, never raised. Score ids are minted (``scr-N``).
* **mitigate()** books one declared treatment decision against a booked
  risk over the pinned strategy vocabulary (avoid / reduce / transfer /
  accept); a risk may be mitigated more than once (an escalation chain).
  Mitigation ids are minted (``mit-N``).
* **report()** is a *pure read* view: a digest-pinned ``AssessmentReport``
  counting risks by category and rating, mitigations by strategy, and the
  still-open risks. It validates seq shape, consumes nothing, and books
  no audit rows.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* risks, *declared* scores, and
*declared* treatments; it cannot prove a hazard really exists, that a
likelihood/impact estimate is accurate, or that a treatment is
effective. Raw title/description/justification text never enters records
and never crosses the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
RISK_ASSESSMENT_VERSION = "risk-assessment.v1"

#: Schema pin carried by records and audit events.
RISK_ASSESSMENT_SCHEMA = "northstar.risk-assessment.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_IDENTIFIED = "risk-assessment.identified"
KIND_SCORED = "risk-assessment.scored"
KIND_MITIGATED = "risk-assessment.mitigated"
KIND_REJECTED = "risk-assessment.rejected"
_KINDS = frozenset({KIND_IDENTIFIED, KIND_SCORED, KIND_MITIGATED, KIND_REJECTED})

#: Pinned risk-category vocabulary (ISO 31000 / NIST SP 800-30 shaped).
CATEGORY_OPERATIONAL = "operational"
CATEGORY_TECHNICAL = "technical"
CATEGORY_SECURITY = "security"
CATEGORY_PRIVACY = "privacy"
CATEGORY_SAFETY = "safety"
CATEGORY_COMPLIANCE = "compliance"
CATEGORY_REPUTATIONAL = "reputational"
CATEGORY_FINANCIAL = "financial"
_CATEGORIES = frozenset(
    {
        CATEGORY_OPERATIONAL,
        CATEGORY_TECHNICAL,
        CATEGORY_SECURITY,
        CATEGORY_PRIVACY,
        CATEGORY_SAFETY,
        CATEGORY_COMPLIANCE,
        CATEGORY_REPUTATIONAL,
        CATEGORY_FINANCIAL,
    }
)

#: Pinned rating vocabulary.
RATING_LOW = "low"
RATING_MODERATE = "moderate"
RATING_HIGH = "high"
RATING_CRITICAL = "critical"
_RATINGS = frozenset({RATING_LOW, RATING_MODERATE, RATING_HIGH, RATING_CRITICAL})

#: Pinned treatment-strategy vocabulary (ISO 31000 risk treatment).
STRATEGY_AVOID = "avoid"
STRATEGY_REDUCE = "reduce"
STRATEGY_TRANSFER = "transfer"
STRATEGY_ACCEPT = "accept"
_STRATEGIES = frozenset(
    {STRATEGY_AVOID, STRATEGY_REDUCE, STRATEGY_TRANSFER, STRATEGY_ACCEPT}
)

#: Rating thresholds over the score (likelihood x impact), exact fractions.
#: low:      score < 15/100
#: moderate: 15/100 <= score < 35/100
#: high:     35/100 <= score < 65/100
#: critical: 65/100 <= score
_THRESHOLD_MODERATE = (15, 100)
_THRESHOLD_HIGH = (35, 100)
_THRESHOLD_CRITICAL = (65, 100)

#: Six-decimal exact scaling for host-reported likelihood/impact.
_SCALE = 1_000_000

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class RiskAssessmentError(Exception):
    """Base class for all risk-assessment errors."""


class BadRiskError(RiskAssessmentError):
    """A risk id is not a usable non-empty str."""


class BadCategoryError(RiskAssessmentError):
    """category is not in the pinned vocabulary."""


class BadDigestError(RiskAssessmentError):
    """A digest is not a non-empty sha256:-prefixed str."""


class UnknownRiskError(RiskAssessmentError):
    """risk_id names no risk this ledger ever saw."""


class BadScoreError(RiskAssessmentError):
    """likelihood/impact is not a finite number in [0,1]."""


class BadStrategyError(RiskAssessmentError):
    """strategy is not in the pinned vocabulary."""


class SeqOrderError(RiskAssessmentError):
    """seq is not a strictly-increasing int."""


class AuditKindError(RiskAssessmentError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadRiskError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadRiskError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadRiskError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_category(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadCategoryError(f"category must be a str, got {type(value).__name__}")
    if value not in _CATEGORIES:
        raise BadCategoryError(f"category {value!r} not in pinned vocabulary")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_score_component(value: Any, what: str) -> int:
    """Validate likelihood/impact and return the 6-decimal scaled int."""
    if isinstance(value, bool):
        raise BadScoreError(f"{what} must be a number, got bool")
    if isinstance(value, int):
        if value not in (0, 1):
            raise BadScoreError(f"{what} int must be 0 or 1, got {value}")
        return value * _SCALE
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadScoreError(f"{what} must be finite, got {value!r}")
        if not 0.0 <= value <= 1.0:
            raise BadScoreError(f"{what} must be in [0,1], got {value!r}")
        return int(round(value * _SCALE))
    raise BadScoreError(f"{what} must be a number, got {type(value).__name__}")


def _check_strategy(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadStrategyError(f"strategy must be a str, got {type(value).__name__}")
    if value not in _STRATEGIES:
        raise BadStrategyError(f"strategy {value!r} not in pinned vocabulary")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        result = _cj.jcs_dumps(payload)  # type: ignore
        return result.encode("utf-8") if isinstance(result, str) else bytes(result)

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise RiskAssessmentError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise RiskAssessmentError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise RiskAssessmentError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def _rating_for(score_num: int, score_den: int) -> str:
    """Pin the rating from the exact score fraction (cross-multiplied, no floats)."""
    for rating, (t_num, t_den) in (
        (RATING_MODERATE, _THRESHOLD_MODERATE),
        (RATING_HIGH, _THRESHOLD_HIGH),
        (RATING_CRITICAL, _THRESHOLD_CRITICAL),
    ):
        if score_num * t_den >= t_num * score_den:
            # score >= threshold: keep climbing; exact comparison below
            pass
    if score_num * _THRESHOLD_MODERATE[1] < _THRESHOLD_MODERATE[0] * score_den:
        return RATING_LOW
    if score_num * _THRESHOLD_HIGH[1] < _THRESHOLD_HIGH[0] * score_den:
        return RATING_MODERATE
    if score_num * _THRESHOLD_CRITICAL[1] < _THRESHOLD_CRITICAL[0] * score_den:
        return RATING_HIGH
    return RATING_CRITICAL


def _reduce_fraction(num: int, den: int) -> Tuple[int, int]:
    g = math.gcd(num, den)
    return (num // g, den // g)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskRecord:
    """One declared risk; title and description are digest-pinned only."""

    risk_id: str
    category: str
    title_digest: str
    description_digest: str
    digest: str
    seq: int
    schema: str = RISK_ASSESSMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.risk_id, self.category, self.title_digest, self.description_digest),
            "risk",
        )


@dataclass(frozen=True)
class ScoreRecord:
    """One declared scoring of a booked risk; arithmetic is exact, no floats."""

    score_id: str
    risk_id: str
    likelihood_text: str
    impact_text: str
    score_text: str
    rating: str
    digest: str
    seq: int
    schema: str = RISK_ASSESSMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.score_id,
                self.risk_id,
                self.likelihood_text,
                self.impact_text,
                self.score_text,
                self.rating,
            ),
            "score",
        )


@dataclass(frozen=True)
class MitigationRecord:
    """One declared treatment decision against a booked risk (an escalation step)."""

    mitigation_id: str
    risk_id: str
    strategy: str
    action_digest: str
    digest: str
    seq: int
    schema: str = RISK_ASSESSMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.mitigation_id, self.risk_id, self.strategy, self.action_digest),
            "mitigation",
        )


@dataclass(frozen=True)
class AssessmentReport:
    """Digest-pinned summary of the ledger's risk posture (pure read view)."""

    total_risks: int
    by_category: Tuple[Tuple[str, int], ...]
    by_rating: Tuple[Tuple[str, int], ...]
    mitigations_applied: int
    by_strategy: Tuple[Tuple[str, int], ...]
    open_risks: Tuple[str, ...]
    digest: str
    seq: int
    schema: str = RISK_ASSESSMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _report_pin(
            self.total_risks,
            self.by_category,
            self.by_rating,
            self.mitigations_applied,
            self.by_strategy,
            self.open_risks,
        )


def _report_pin(
    total: int,
    by_category: Tuple[Tuple[str, int], ...],
    by_rating: Tuple[Tuple[str, int], ...],
    mitigations: int,
    by_strategy: Tuple[Tuple[str, int], ...],
    open_risks: Tuple[str, ...],
) -> str:
    return _digest_pin(
        (
            total,
            tuple(sorted(by_category)),
            tuple(sorted(by_rating)),
            mitigations,
            tuple(sorted(by_strategy)),
            tuple(open_risks),
        ),
        "assessment-report",
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def risk_assessment_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw risk text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "title",
        "description",
        "action",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "justification",
        "explanation",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "risk-assessment",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# RiskAssessment ledger
# ---------------------------------------------------------------------------


class RiskAssessment:
    """Risk management bookkeeping ledger: identify, score, mitigate."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # risk_id -> RiskRecord (ordered)
        self._risks: Dict[str, RiskRecord] = {}
        # score_id -> ScoreRecord (ordered)
        self._scores: Dict[str, ScoreRecord] = {}
        # mitigation_id -> MitigationRecord (ordered)
        self._mitigations: Dict[str, MitigationRecord] = {}
        # risk_id -> count of mitigations booked against it
        self._mitigation_counts: Dict[str, int] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(risk_assessment_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: RiskAssessmentError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def identify(
        self,
        category: str,
        seq: int,
        title_digest: str = "",
        description_digest: str = "",
    ) -> RiskRecord:
        """Book a declared risk. Title and description are pinned by digest only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                category = _check_category(category)
                title_digest = _check_digest(title_digest, "title_digest", allow_empty=True)
                description_digest = _check_digest(
                    description_digest, "description_digest", allow_empty=True
                )
            except RiskAssessmentError as exc:
                self._fail(seq, exc, category=str(category))
            risk_id = f"risk-{len(self._risks) + 1}"
            record = RiskRecord(
                risk_id=risk_id,
                category=category,
                title_digest=title_digest,
                description_digest=description_digest,
                digest=_digest_pin(
                    (risk_id, category, title_digest, description_digest),
                    "risk",
                ),
                seq=seq,
            )
            self._risks[risk_id] = record
            self._mitigation_counts[risk_id] = 0
            self._emit(
                KIND_IDENTIFIED,
                seq,
                risk_id=risk_id,
                category=category,
                title_digest=title_digest,
                description_digest=description_digest,
                record_digest=record.digest,
            )
            return record

    def score(
        self,
        risk_id: str,
        seq: int,
        likelihood: Any,
        impact: Any,
    ) -> ScoreRecord:
        """Book a declared scoring of a booked risk.

        Host-reported likelihood and impact in [0,1] (GIGO); the risk score
        is derived by exact integer arithmetic and the rating is pinned.
        Verdicts are data, never raised.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                risk_id = _check_id(risk_id, "risk_id")
                l_scaled = _check_score_component(likelihood, "likelihood")
                i_scaled = _check_score_component(impact, "impact")
            except RiskAssessmentError as exc:
                self._fail(seq, exc, risk_id=str(risk_id))
            if risk_id not in self._risks:
                self._fail(
                    seq,
                    UnknownRiskError(f"unknown risk: {risk_id!r}"),
                    risk_id=risk_id,
                )
            score_num, score_den = _reduce_fraction(l_scaled * i_scaled, _SCALE * _SCALE)
            l_num, l_den = _reduce_fraction(l_scaled, _SCALE)
            i_num, i_den = _reduce_fraction(i_scaled, _SCALE)
            rating = _rating_for(score_num, score_den)
            score_id = f"scr-{len(self._scores) + 1}"
            record = ScoreRecord(
                score_id=score_id,
                risk_id=risk_id,
                likelihood_text=f"{l_num}/{l_den}",
                impact_text=f"{i_num}/{i_den}",
                score_text=f"{score_num}/{score_den}",
                rating=rating,
                digest=_digest_pin(
                    (
                        score_id,
                        risk_id,
                        f"{l_num}/{l_den}",
                        f"{i_num}/{i_den}",
                        f"{score_num}/{score_den}",
                        rating,
                    ),
                    "score",
                ),
                seq=seq,
            )
            self._scores[score_id] = record
            self._emit(
                KIND_SCORED,
                seq,
                risk_id=risk_id,
                score_id=score_id,
                likelihood_text=record.likelihood_text,
                impact_text=record.impact_text,
                score_text=record.score_text,
                rating=rating,
                record_digest=record.digest,
            )
            return record

    def mitigate(
        self,
        risk_id: str,
        seq: int,
        strategy: str,
        action_digest: str = "",
    ) -> MitigationRecord:
        """Book a declared treatment decision against a booked risk.

        A risk may be mitigated more than once (an escalation chain);
        each decision is a new ``MitigationRecord``.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                risk_id = _check_id(risk_id, "risk_id")
                strategy = _check_strategy(strategy)
                action_digest = _check_digest(action_digest, "action_digest", allow_empty=True)
            except RiskAssessmentError as exc:
                self._fail(seq, exc, risk_id=str(risk_id))
            if risk_id not in self._risks:
                self._fail(
                    seq,
                    UnknownRiskError(f"unknown risk: {risk_id!r}"),
                    risk_id=risk_id,
                )
            mitigation_id = f"mit-{len(self._mitigations) + 1}"
            record = MitigationRecord(
                mitigation_id=mitigation_id,
                risk_id=risk_id,
                strategy=strategy,
                action_digest=action_digest,
                digest=_digest_pin(
                    (mitigation_id, risk_id, strategy, action_digest),
                    "mitigation",
                ),
                seq=seq,
            )
            self._mitigations[mitigation_id] = record
            self._mitigation_counts[risk_id] += 1
            self._emit(
                KIND_MITIGATED,
                seq,
                risk_id=risk_id,
                mitigation_id=mitigation_id,
                strategy=strategy,
                action_digest=action_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def risk(self, risk_id: str, seq: int) -> Optional[RiskRecord]:
        """Pure read: the booked risk record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._risks.get(risk_id)

    def risk_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of booked risks, in booking order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._risks)

    def scores_for(self, risk_id: str, seq: int) -> Tuple[ScoreRecord, ...]:
        """Pure read: scores booked for a risk, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(s for s in self._scores.values() if s.risk_id == risk_id)

    def mitigations_for(self, risk_id: str, seq: int) -> Tuple[MitigationRecord, ...]:
        """Pure read: mitigation decisions booked for a risk, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(m for m in self._mitigations.values() if m.risk_id == risk_id)

    def is_mitigated(self, risk_id: str, seq: int) -> bool:
        """Pure read: whether a booked risk has at least one mitigation."""
        _check_seq(seq)
        with self._lock:
            if risk_id not in self._risks:
                raise UnknownRiskError(f"unknown risk: {risk_id!r}")
            return self._mitigation_counts.get(risk_id, 0) > 0

    def report(self, seq: int) -> AssessmentReport:
        """Pure read: digest-pinned posture report. Consumes no seq, books no rows.

        The latest score per risk decides its rating bucket; risks never
        scored are bucketed under ``unscored``.
        """
        _check_seq(seq)
        with self._lock:
            latest_rating: Dict[str, str] = {}
            for score in self._scores.values():
                latest_rating[score.risk_id] = score.rating
            by_category: Dict[str, int] = {}
            by_rating: Dict[str, int] = {}
            open_ids: List[str] = []
            for rid, risk in self._risks.items():
                by_category[risk.category] = by_category.get(risk.category, 0) + 1
                bucket = latest_rating.get(rid, "unscored")
                by_rating[bucket] = by_rating.get(bucket, 0) + 1
                if self._mitigation_counts.get(rid, 0) == 0:
                    open_ids.append(rid)
            by_strategy: Dict[str, int] = {}
            for mit in self._mitigations.values():
                by_strategy[mit.strategy] = by_strategy.get(mit.strategy, 0) + 1
            report = AssessmentReport(
                total_risks=len(self._risks),
                by_category=tuple(sorted(by_category.items())),
                by_rating=tuple(sorted(by_rating.items())),
                mitigations_applied=len(self._mitigations),
                by_strategy=tuple(sorted(by_strategy.items())),
                open_risks=tuple(open_ids),
                digest=_report_pin(
                    len(self._risks),
                    tuple(sorted(by_category.items())),
                    tuple(sorted(by_rating.items())),
                    len(self._mitigations),
                    tuple(sorted(by_strategy.items())),
                    tuple(open_ids),
                ),
                seq=seq,
            )
            return report

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "risks": len(self._risks),
                "scores": len(self._scores),
                "mitigations": len(self._mitigations),
                "open": sum(1 for r in self._risks if self._mitigation_counts.get(r, 0) == 0),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: identify, score, mitigate, report."""
    ledger = RiskAssessment()
    risk = ledger.identify(
        "security",
        1,
        title_digest="sha256:" + "a" * 64,
        description_digest="sha256:" + "b" * 64,
    )
    assert risk.verify()
    assert risk.risk_id == "risk-1"
    scr = ledger.score(risk.risk_id, 2, 0.5, 0.8)
    assert scr.verify()
    assert scr.score_id == "scr-1"
    assert scr.likelihood_text == "1/2"
    assert scr.impact_text == "4/5"
    assert scr.score_text == "2/5"
    assert scr.rating == "high"  # 0.4 in [0.35, 0.65)
    mit = ledger.mitigate(
        risk.risk_id, 3, "reduce", action_digest="sha256:" + "c" * 64
    )
    assert mit.verify()
    assert mit.mitigation_id == "mit-1"
    # escalation: a second mitigation on the same risk is allowed
    mit2 = ledger.mitigate(risk.risk_id, 4, "transfer")
    assert mit2.verify() and mit2.mitigation_id == "mit-2"
    assert ledger.is_mitigated(risk.risk_id, 4)
    risk2 = ledger.identify("safety", 5)
    assert risk2.verify()
    report = ledger.report(6)
    assert report.verify()
    assert report.total_risks == 2
    assert report.mitigations_applied == 2
    assert dict(report.by_category) == {"safety": 1, "security": 1}
    assert dict(report.by_rating) == {"high": 1, "unscored": 1}
    assert dict(report.by_strategy) == {"reduce": 1, "transfer": 1}
    assert report.open_risks == ("risk-2",)
    print("risk-assessment OK: identify, score, mitigate, report, pins")


if __name__ == "__main__":
    main()
