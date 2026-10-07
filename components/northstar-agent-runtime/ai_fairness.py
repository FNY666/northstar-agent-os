"""AI fairness assessment/mitigation (assess/mitigate/verify), simulated.

Research motivation: fairness criteria (IBM AI Fairness 360, Fairlearn,
What-If Tool -- disparate impact, statistical parity, equalized odds,
calibration, counterfactual and individual fairness) all reduce
governance to one operational shape: a fairness issue is declared
against a pinned dimension vocabulary, a mitigation is declared
against a pinned strategy vocabulary, and the ledger pins every
declaration with a ``sha256:`` digest so later reads can re-derive it.

This module is the *AI-fairness decision ledger* half of that shape:

- ``AIFairness.assess(system_id, dimension, verdict, seq,
  assessment_digest="")`` -- book one declared fairness assessment
  over the pinned 8-dimension vocabulary x the pinned 5-verdict
  vocabulary. The assessment's content (group attributes, outcome
  rates, transcripts) travels as digest pins only; raw values never
  enter a record. First assess on an id registers the system.
- ``AIFairness.mitigate(assessment_id, seq, strategy="reweight",
  mitigation_digest="")`` -- book one declared mitigation over the
  pinned 8-strategy vocabulary. Mitigations are chainable (a declared
  failure may book a declared follow-up); bookings are declarations,
  never proof a pipeline changed.
- ``AIFairness.verify(record_id, seq)`` -- **pure read** (seq shape
  validated, never consumed, no audit row). Re-derives the digest pin
  of any assessment or mitigation record; the ``verified``/``tampered``
  verdict is *data* (tamper reported, never raised), never proof the
  system is fair.
- ``AIFairness.retire(system_id, seq, reason="manual")`` -- terminal.
  Ids are never recycled; post-retire mutations are refused, reads
  still work.
- Pure-read views (``assessment_record`` / ``mitigation_record`` /
  ``assessments_for`` / ``mitigations_for`` / ``system_ids`` /
  ``retired_ids`` / ``stats`` / ``audit_log``) -- seq shape validated,
  never consumed, no audit rows.
- ``ai_fairness_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``assessed`` / ``mitigated`` / ``retired`` / ``rejected``);
  caller-supplied seqs only. Group attributes, scores, and raw
  material never cross the audit boundary -- rows carry ids, pinned
  dimension/verdict/strategy labels, digests, and counts only.

Distinct layer: ``fairness_eval.py`` owns the bias-*measurement*
mechanics (declared group outcome rates, deterministic disparity
arithmetic, metric-level mitigation bookkeeping). ``ai_ethics.py``
owns per-system ethics assessments. This module owns the per-system
*fairness assessment -> declared mitigation* governance ledger none
of them own.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``assessment_id`` / ``mitigation_id`` must be
  non-empty str, <= 256 chars, no whitespace.
- ``dimension`` must be in the pinned 8-dimension vocabulary;
  ``verdict`` in the pinned 5-verdict vocabulary; ``strategy`` in the
  pinned 8-strategy vocabulary.
- Digests must be ``sha256:<64hex>`` when supplied (may be empty).
- ``assess`` on a retired system, ``mitigate`` on an unknown or
  retired assessment, ``verify`` on an unknown record raise.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* fairness assessments and mitigations
  reported by the host. A booked ``fair`` verdict means the host
  declared one -- the module measured nothing, computed no fairness
  metric, and proves nothing about any real system's fairness, bias,
  or safety.
- Digest pins prove ledger integrity and ordering, never the truth of
  any assessment, the effectiveness of any mitigation, or the fairness
  of any system.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if fairness state must survive a restart.
"""

from __future__ import annotations

import ast
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
AI_FAIRNESS_VERSION = "ai-fairness.v1"

#: Schema pin carried by records and audit events.
AI_FAIRNESS_SCHEMA = "northstar.ai-fairness.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ASSESSED = "assessed"
KIND_MITIGATED = "mitigated"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
KINDS = (KIND_ASSESSED, KIND_MITIGATED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw material never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "assessment_text",
     "rationale", "metric", "score", "data", "record", "trace",
     "transcript", "weights", "policy", "model_output", "judgment",
     "decision_text", "note", "comment", "group", "groups",
     "protected_group", "attribute", "attributes", "outcome_rate",
     "outcome_rates", "sample", "samples", "dataset", "prompt",
     "response", "label", "labels"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned fairness-dimension vocabulary (AIF360 / Fairlearn shaped).
DIM_DISPARATE_IMPACT = "disparate-impact"
DIM_STATISTICAL_PARITY = "statistical-parity"
DIM_EQUALIZED_ODDS = "equalized-odds"
DIM_DEMOGRAPHIC_PARITY = "demographic-parity"
DIM_EQUAL_OPPORTUNITY = "equal-opportunity"
DIM_CALIBRATION = "calibration"
DIM_COUNTERFACTUAL = "counterfactual-fairness"
DIM_INDIVIDUAL = "individual-fairness"
DIMENSIONS = (
    DIM_DISPARATE_IMPACT,
    DIM_STATISTICAL_PARITY,
    DIM_EQUALIZED_ODDS,
    DIM_DEMOGRAPHIC_PARITY,
    DIM_EQUAL_OPPORTUNITY,
    DIM_CALIBRATION,
    DIM_COUNTERFACTUAL,
    DIM_INDIVIDUAL,
)

#: Pinned fairness-verdict vocabulary. Verdicts are host-reported data.
VERDICT_FAIR = "fair"
VERDICT_UNFAIR = "unfair"
VERDICT_MARGINAL = "marginal"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_ASSESSED = "not-assessed"
VERDICTS = (
    VERDICT_FAIR,
    VERDICT_UNFAIR,
    VERDICT_MARGINAL,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_ASSESSED,
)

#: Pinned mitigation-strategy vocabulary. Bookings are declarations.
STRAT_REWEIGHT = "reweight"
STRAT_RESAMPLE = "resample"
STRAT_THRESHOLD_OPTIMIZE = "threshold-optimize"
STRAT_CONSTRAIN = "constrain"
STRAT_ADVERSARIAL = "adversarial-debiasing"
STRAT_CALIBRATION = "calibration-adjust"
STRAT_DATA_AUGMENT = "data-augmentation"
STRAT_NO_ACTION = "no-action"
STRATEGIES = (
    STRAT_REWEIGHT,
    STRAT_RESAMPLE,
    STRAT_THRESHOLD_OPTIMIZE,
    STRAT_CONSTRAIN,
    STRAT_ADVERSARIAL,
    STRAT_CALIBRATION,
    STRAT_DATA_AUGMENT,
    STRAT_NO_ACTION,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_POLICY_CHANGE = "policy-change"
REASON_NON_COMPLIANCE = "non-compliance"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_POLICY_CHANGE,
    REASON_NON_COMPLIANCE,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Modules this file may import (the canonical_json fallback + stdlib).
_STDLIB_IMPORTS = frozenset(
    {"__future__", "ast", "hashlib", "re", "threading", "dataclasses",
     "typing", "json"})


class AIFairnessError(Exception):
    """Base error for the AI-fairness ledger (programming errors)."""


class BadIdError(AIFairnessError):
    """Raised when a system/assessment/mitigation id is malformed."""


class DuplicateAssessmentError(AIFairnessError):
    """Raised when a minted assessment id somehow collides (never)."""


class UnknownSystemError(AIFairnessError):
    """Raised when a system id names no assessed system."""


class UnknownAssessmentError(AIFairnessError):
    """Raised when an assessment id names no booked assessment."""


class UnknownRecordError(AIFairnessError):
    """Raised when a record id names neither an assessment nor a mitigation."""


class RetiredSystemError(AIFairnessError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AIFairnessError):
    """Raised when retiring an already-retired system."""


class BadDimensionError(AIFairnessError):
    """Raised when a dimension is not in the pinned vocabulary."""


class BadVerdictError(AIFairnessError):
    """Raised when a verdict is not in the pinned vocabulary."""


class BadStrategyError(AIFairnessError):
    """Raised when a mitigation strategy is not in the pinned vocabulary."""


class BadDigestError(AIFairnessError):
    """Raised when a digest is not a sha256: pin."""


class BadReasonError(AIFairnessError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIFairnessError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIFairnessError):
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
        "domain": AI_FAIRNESS_SCHEMA,
        "parts": list(parts),
    })


def ai_fairness_audit_event(kind: str, detail: Dict[str, object],
                            seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-fairness ledger."""
    if kind not in KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_FAIRNESS_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    tree = ast.parse(open(__file__, encoding="utf-8").read())
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            seen.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                seen.add(node.module.split(".")[0])
    return seen <= (_STDLIB_IMPORTS | {"canonical_json"})


@dataclass(frozen=True)
class AssessmentRecord:
    """Frozen record of one declared fairness assessment (digest-pinned)."""
    assessment_id: str
    system_id: str
    dimension: str
    verdict: str
    assessment_digest: str
    seq: int
    digest: str

    def verify(self, assessment_id: str, system_id: str, dimension: str,
               verdict: str, assessment_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "assessment", assessment_id, system_id, dimension, verdict,
            assessment_digest, self.seq)


@dataclass(frozen=True)
class MitigationRecord:
    """Frozen record of one declared fairness mitigation (digest-pinned)."""
    mitigation_id: str
    assessment_id: str
    system_id: str
    strategy: str
    mitigation_digest: str
    seq: int
    digest: str

    def verify(self, mitigation_id: str, assessment_id: str, system_id: str,
               strategy: str, mitigation_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "mitigation", mitigation_id, assessment_id, system_id,
            strategy, mitigation_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    record_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, record_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", record_id, verdict, self.seq)


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


class AIFairness:
    """AI-fairness assessment/mitigation ledger (declared, digest-pinned)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._mitigations_by_assessment: Dict[str, Tuple[str, ...]] = {}
        self._assessment_ids: Tuple[str, ...] = ()
        self._mitigation_ids: Tuple[str, ...] = ()
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
        event = ai_fairness_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_fairness_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def assess(self, system_id: str, dimension: str, verdict: str, seq: int,
               assessment_digest: str = "") -> AssessmentRecord:
        """Book one declared fairness assessment. First assess on an id
        registers the system. Pins the assessment digest, never the
        assessment content. Returns the frozen ``AssessmentRecord``
        (minted ``asr-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(dimension, bool) or not isinstance(dimension, str):
                raise BadDimensionError(
                    f"dimension must be str, got {type(dimension).__name__}")
            if dimension not in DIMENSIONS:
                raise BadDimensionError(
                    f"dimension must be one of {sorted(DIMENSIONS)}, "
                    f"got {dimension!r}")
            if isinstance(verdict, bool) or not isinstance(verdict, str):
                raise BadVerdictError(
                    f"verdict must be str, got {type(verdict).__name__}")
            if verdict not in VERDICTS:
                raise BadVerdictError(
                    f"verdict must be one of {sorted(VERDICTS)}, "
                    f"got {verdict!r}")
            assessment_digest = _check_digest(
                assessment_digest, "assessment_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                assessment_id = f"asr-{len(self._assessment_ids) + 1}"
                if assessment_id in self._assessments:
                    raise DuplicateAssessmentError(
                        f"assessment id collision: {assessment_id!r}")
                record = AssessmentRecord(
                    assessment_id=assessment_id,
                    system_id=system_id,
                    dimension=dimension,
                    verdict=verdict,
                    assessment_digest=assessment_digest,
                    seq=seq,
                    digest=_pin("assessment", assessment_id, system_id,
                                dimension, verdict, assessment_digest, seq),
                )
                self._assessments[assessment_id] = record
                self._assessment_ids = self._assessment_ids + (assessment_id,)
                self._by_system[system_id] = (
                    self._by_system.get(system_id, ()) + (assessment_id,))
        except AIFairnessError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_ASSESSED,
                   {"system_id": system_id,
                    "assessment_id": record.assessment_id,
                    "dimension": dimension,
                    "verdict": verdict,
                    "assessment_digest": assessment_digest}, seq)
        return record

    def mitigate(self, assessment_id: str, seq: int,
                 strategy: str = STRAT_REWEIGHT,
                 mitigation_digest: str = "") -> MitigationRecord:
        """Book one declared fairness mitigation. Mitigations are
        chainable (a declared failure may book a declared follow-up);
        bookings are declarations, never proof a pipeline changed.
        Returns the frozen ``MitigationRecord`` (minted ``mit-N``)."""
        self._claim(seq)
        try:
            assessment_id = _check_id(assessment_id, "assessment_id")
            if isinstance(strategy, bool) or not isinstance(strategy, str):
                raise BadStrategyError(
                    f"strategy must be str, got {type(strategy).__name__}")
            if strategy not in STRATEGIES:
                raise BadStrategyError(
                    f"strategy must be one of {sorted(STRATEGIES)}, "
                    f"got {strategy!r}")
            mitigation_digest = _check_digest(
                mitigation_digest, "mitigation_digest", allow_empty=True)
            with self._lock:
                if assessment_id not in self._assessments:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}")
                rec = self._assessments[assessment_id]
                system_id = rec.system_id
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                mitigation_id = f"mit-{len(self._mitigation_ids) + 1}"
                record = MitigationRecord(
                    mitigation_id=mitigation_id,
                    assessment_id=assessment_id,
                    system_id=system_id,
                    strategy=strategy,
                    mitigation_digest=mitigation_digest,
                    seq=seq,
                    digest=_pin("mitigation", mitigation_id, assessment_id,
                                system_id, strategy, mitigation_digest, seq),
                )
                self._mitigations[mitigation_id] = record
                self._mitigation_ids = self._mitigation_ids + (mitigation_id,)
                self._mitigations_by_assessment[assessment_id] = (
                    self._mitigations_by_assessment.get(assessment_id, ())
                    + (mitigation_id,))
        except AIFairnessError:
            self._burn(
                seq,
                assessment_id if isinstance(assessment_id, str) else "")
            raise
        self._emit(KIND_MITIGATED,
                   {"system_id": system_id,
                    "assessment_id": assessment_id,
                    "mitigation_id": record.mitigation_id,
                    "strategy": strategy,
                    "mitigation_digest": mitigation_digest}, seq)
        return record

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive an assessment's or mitigation's digest pin.
        The ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        record_id = _check_id(record_id, "record_id")
        with self._lock:
            rec = self._assessments.get(record_id)
            if rec is not None:
                intact = rec.verify(
                    rec.assessment_id, rec.system_id, rec.dimension,
                    rec.verdict, rec.assessment_digest)
            else:
                mrec = self._mitigations.get(record_id)
                if mrec is None:
                    raise UnknownRecordError(
                        f"unknown record: {record_id!r}")
                intact = mrec.verify(
                    mrec.mitigation_id, mrec.assessment_id, mrec.system_id,
                    mrec.strategy, mrec.mitigation_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                record_id=record_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", record_id, verdict, seq),
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
                if system_id not in self._by_system:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                record = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", system_id, reason, seq),
                )
                self._retired[system_id] = record
        except AIFairnessError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    # -- pure-read views --------------------------------------------------

    def assessment_record(self, assessment_id: str,
                          seq: int) -> AssessmentRecord:
        """Pure read: fetch a booked assessment record by id."""
        _check_seq(seq)
        assessment_id = _check_id(assessment_id, "assessment_id")
        with self._lock:
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return self._assessments[assessment_id]

    def mitigation_record(self, mitigation_id: str,
                          seq: int) -> MitigationRecord:
        """Pure read: fetch a booked mitigation record by id."""
        _check_seq(seq)
        mitigation_id = _check_id(mitigation_id, "mitigation_id")
        with self._lock:
            if mitigation_id not in self._mitigations:
                raise UnknownRecordError(
                    f"unknown mitigation: {mitigation_id!r}")
            return self._mitigations[mitigation_id]

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read: assessment ids booked against a system."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def mitigations_for(self, assessment_id: str,
                        seq: int) -> Tuple[str, ...]:
        """Pure read: mitigation ids booked against an assessment."""
        _check_seq(seq)
        assessment_id = _check_id(assessment_id, "assessment_id")
        with self._lock:
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return self._mitigations_by_assessment.get(assessment_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of all registered systems."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_system)

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of all retired systems."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired)

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """Pure read: the ordered audit event log."""
        _check_seq(seq)
        with self._lock:
            return self._audit

    def stats(self, seq: int) -> Dict[str, int]:
        """Pure read: counts of records held by the ledger."""
        _check_seq(seq)
        with self._lock:
            return {
                "systems": len(self._by_system),
                "assessments": len(self._assessments),
                "mitigations": len(self._mitigations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: assess -> mitigate -> verify -> retire over one ledger."""
    ledger = AIFairness()
    a = ledger.assess("sys-1", DIM_DISPARATE_IMPACT, VERDICT_UNFAIR, 1)
    assert a.assessment_id == "asr-1"
    m = ledger.mitigate(a.assessment_id, 2, strategy=STRAT_REWEIGHT)
    assert m.mitigation_id == "mit-1"
    assert ledger.verify(a.assessment_id, 3).verdict == "verified"
    assert ledger.verify(m.mitigation_id, 4).verdict == "verified"
    assert ledger.stats(5)["assessments"] == 1
    ledger.retire("sys-1", 6)
    assert ledger.retired_ids(7) == ("sys-1",)
    print("ai-fairness OK: assess, mitigate, verify, retire, pins, audit")


if __name__ == "__main__":
    main()
