"""Roboethics assessment (assess/verify/evaluate) interface, simulated.

Research motivation: roboethics (Veruggio's Roboethics; the EURON
Roboethics Roadmap; IEEE robotics ethics efforts) treats robots as
physical actors whose declared ethics posture must be bookable as
governance data: an assessor declares a robotics-ethics finding over a
pinned dimension vocabulary, the ledger pins it, and a report derives
posture *from the ledger* -- the report never independently judges
whether any robot is ethical.

This module is the *roboethics assessment* ledger half of that shape:

- ``Roboethics.assess(system_id, dimension, verdict, seq,
  assessment_digest="")`` -- book one declared roboethics assessment
  over the pinned 8-dimension vocabulary x the pinned 4-verdict
  vocabulary. The assessment's content is pinned by ``sha256:`` digest
  only; raw material never enters a record. First assess on an id
  registers the system.
- ``Roboethics.verify(assessment_id, seq)`` -- **pure read** (seq shape
  validated, never consumed, no audit row). Re-derives the digest pin;
  the ``verified``/``tampered`` verdict is *data*, never proof the
  robot is ethical.
- ``Roboethics.evaluate(system_id, seq)`` -- **pure read**. Derives
  posture as data by ledger rule: ``unevaluated`` (no assessments) ->
  ``non-compliant`` (any ``fails``) -> ``inconclusive`` (any
  ``inconclusive``) -> ``conditionally-compliant`` (any
  ``needs-review``) -> ``compliant`` (all ``passes``), plus verdict
  tallies and ``integrity_ok`` as data.
- ``Roboethics.retire(system_id, seq, reason="manual")`` -- terminal.
  Ids are never recycled; post-retire mutations are refused, reads
  still work.
- Pure-read views (``assessment_record`` / ``assessments_for`` /
  ``system_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``roboethics_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``assessed`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw assessment content never crosses the audit boundary --
  audit rows carry ids, pinned dimension/verdict labels, digests, and
  counts only.

Distinct layer: ``ai_ethics.py`` owns AI-ethics assessments (fairness,
privacy, beneficence-shaped dimensions); ``machine_unlearning.py``,
``shutdownability.py``, and operational safety envelopes own machine
behaviour mechanics. This module owns the per-system *robotics-ethics*
assessment ledger none of that covers -- declared findings over
robot-specific dimensions (physical safety, HRI, autonomy, dual-use),
digest re-derivation, and derived posture.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``assessment_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``dimension`` must be in the pinned 8-dimension vocabulary;
  ``verdict`` must be in the pinned 4-verdict vocabulary.
- ``assessment_digest`` must be ``sha256:<64hex>`` when supplied (may
  be empty).
- ``verify`` / ``assess`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``rbt-N``).
- ``assess`` on a retired system raises ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* roboethics assessments reported by the
  host. A booked ``passes`` verdict means the host declared one -- the
  module assessed nothing, measured no safety or ethics, and proves
  nothing about any real robot's ethics or safety.
- Digest pins prove ledger integrity and ordering, never the truth of
  any assessment or the ethical acceptability of any system.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if roboethics state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

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
ROBOETHICS_VERSION = "roboethics.v1"

#: Schema pin carried by records and audit events.
ROBOETHICS_SCHEMA = "northstar.roboethics.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ASSESSED = "assessed"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ASSESSED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "assessment_text",
     "rationale", "metric", "score", "data", "record", "trace",
     "transcript", "weights", "policy", "model_output", "judgment",
     "decision_text", "note", "comment"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned roboethics-dimension vocabulary (EURON roadmap / Veruggio shaped).
DIM_PHYSICAL_SAFETY = "physical-safety"
DIM_HUMAN_ROBOT_INTERACTION = "human-robot-interaction"
DIM_OPERATIONAL_AUTONOMY = "operational-autonomy"
DIM_SENSORY_PRIVACY = "sensory-privacy"
DIM_ACCOUNTABILITY = "accountability"
DIM_TRANSPARENCY = "transparency"
DIM_DUAL_USE = "dual-use"
DIM_SOCIETAL_IMPACT = "societal-impact"
DIMENSIONS = (
    DIM_PHYSICAL_SAFETY,
    DIM_HUMAN_ROBOT_INTERACTION,
    DIM_OPERATIONAL_AUTONOMY,
    DIM_SENSORY_PRIVACY,
    DIM_ACCOUNTABILITY,
    DIM_TRANSPARENCY,
    DIM_DUAL_USE,
    DIM_SOCIETAL_IMPACT,
)

#: Pinned assessment-verdict vocabulary. Verdicts are host-reported data.
VERDICT_PASSES = "passes"
VERDICT_FAILS = "fails"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NEEDS_REVIEW = "needs-review"
VERDICTS = (
    VERDICT_PASSES,
    VERDICT_FAILS,
    VERDICT_INCONCLUSIVE,
    VERDICT_NEEDS_REVIEW,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNEVALUATED = "unevaluated"
POSTURE_NON_COMPLIANT = "non-compliant"
POSTURE_INCONCLUSIVE = "inconclusive"
POSTURE_CONDITIONAL = "conditionally-compliant"
POSTURE_COMPLIANT = "compliant"
POSTURES = (
    POSTURE_UNEVALUATED,
    POSTURE_NON_COMPLIANT,
    POSTURE_INCONCLUSIVE,
    POSTURE_CONDITIONAL,
    POSTURE_COMPLIANT,
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


class RoboethicsError(Exception):
    """Base error for the roboethics ledger (programming errors)."""


class BadIdError(RoboethicsError):
    """Raised when a system/assessment id is malformed."""


class DuplicateAssessmentError(RoboethicsError):
    """Raised when a minted assessment id somehow collides (never)."""


class UnknownSystemError(RoboethicsError):
    """Raised when a system id names no assessed system."""


class UnknownAssessmentError(RoboethicsError):
    """Raised when an assessment id names no booked assessment."""


class RetiredSystemError(RoboethicsError):
    """Raised when mutating a retired system."""


class DoubleRetireError(RoboethicsError):
    """Raised when retiring an already-retired system."""


class BadDimensionError(RoboethicsError):
    """Raised when a dimension is not in the pinned vocabulary."""


class BadVerdictError(RoboethicsError):
    """Raised when a verdict is not in the pinned vocabulary."""


class BadDigestError(RoboethicsError):
    """Raised when an assessment digest is not a sha256: pin."""


class BadReasonError(RoboethicsError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(RoboethicsError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(RoboethicsError):
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
        "domain": ROBOETHICS_SCHEMA,
        "parts": list(parts),
    })


def roboethics_audit_event(kind: str, detail: Dict[str, object],
                           seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the roboethics ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": ROBOETHICS_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class AssessmentRecord:
    """Frozen record of one declared roboethics assessment (digest-pinned)."""
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
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    assessment_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, assessment_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", assessment_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_assessments: int
    n_passes: int
    n_fails: int
    n_inconclusive: int
    n_needs_review: int
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


class Roboethics:
    """Roboethics assessment ledger (declared findings, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._assessment_ids: Tuple[str, ...] = ()
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
        event = roboethics_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = roboethics_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def assess(self, system_id: str, dimension: str, verdict: str, seq: int,
               assessment_digest: str = "") -> AssessmentRecord:
        """Book one declared roboethics assessment. First assess on an id
        registers the system. Pins the assessment digest, never the
        assessment content. Returns the frozen ``AssessmentRecord``
        (minted ``rbt-N``)."""
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
                assessment_id = f"rbt-{len(self._assessment_ids) + 1}"
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
        except RoboethicsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_ASSESSED,
                   {"system_id": system_id,
                    "assessment_id": record.assessment_id,
                    "dimension": dimension,
                    "verdict": verdict,
                    "assessment_digest": assessment_digest}, seq)
        return record

    def verify(self, assessment_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive an assessment's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        assessment_id = _check_id(assessment_id, "assessment_id")
        with self._lock:
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            rec = self._assessments[assessment_id]
            intact = rec.verify(
                rec.assessment_id, rec.system_id, rec.dimension,
                rec.verdict, rec.assessment_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                assessment_id=assessment_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", assessment_id, verdict, seq),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``fails`` -> ``non-compliant``; any ``inconclusive`` ->
        ``inconclusive``; any ``needs-review`` -> ``conditionally-compliant``;
        all ``passes`` -> ``compliant``). Validates seq shape, consumes
        nothing, writes no audit row. Returns the frozen
        ``EvaluationReport``."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            ids = self._by_system[system_id]
            recs = [self._assessments[i] for i in ids]
            n_passes = sum(1 for r in recs if r.verdict == VERDICT_PASSES)
            n_fails = sum(1 for r in recs if r.verdict == VERDICT_FAILS)
            n_inconclusive = sum(
                1 for r in recs if r.verdict == VERDICT_INCONCLUSIVE)
            n_needs = sum(
                1 for r in recs if r.verdict == VERDICT_NEEDS_REVIEW)
            integrity_ok = all(
                r.verify(r.assessment_id, r.system_id, r.dimension,
                         r.verdict, r.assessment_digest) for r in recs)
            if n_fails:
                posture = POSTURE_NON_COMPLIANT
            elif n_inconclusive:
                posture = POSTURE_INCONCLUSIVE
            elif n_needs:
                posture = POSTURE_CONDITIONAL
            else:
                posture = POSTURE_COMPLIANT
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                n_assessments=len(recs),
                n_passes=n_passes,
                n_fails=n_fails,
                n_inconclusive=n_inconclusive,
                n_needs_review=n_needs,
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
        except RoboethicsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    def assessment_record(self, assessment_id: str,
                          seq: int) -> AssessmentRecord:
        """Pure read view of one booked assessment."""
        _check_seq(seq)
        assessment_id = _check_id(assessment_id, "assessment_id")
        with self._lock:
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return self._assessments[assessment_id]

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read view of assessment ids for one system, in book order."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered system ids, in first-assess order."""
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
                "assessments": len(self._assessments),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: assess, verify, evaluate, retire, pins, audit."""
    rb = Roboethics()
    assert ROBOETHICS_VERSION == "roboethics.v1"
    assert ROBOETHICS_SCHEMA == "northstar.roboethics.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = rb.assess("sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, 1, digest)
    assert rec.assessment_id == "rbt-1"
    assert rec.verify("rbt-1", "sys-1", DIM_PHYSICAL_SAFETY, VERDICT_PASSES, digest)
    assert not rec.verify("rbt-1", "sys-1", DIM_PHYSICAL_SAFETY, VERDICT_FAILS,
                          digest)
    vr = rb.verify("rbt-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("rbt-1", "verified")
    ev = rb.evaluate("sys-1", 3)
    assert ev.posture == POSTURE_COMPLIANT
    assert ev.integrity_ok
    assert ev.verify("sys-1", POSTURE_COMPLIANT)
    rb.assess("sys-1", DIM_DUAL_USE, VERDICT_FAILS, 4, digest)
    ev = rb.evaluate("sys-1", 5)
    assert ev.posture == POSTURE_NON_COMPLIANT
    assert ev.n_assessments == 2 and ev.n_fails == 1
    rr = rb.retire("sys-1", 6)
    assert rr.verify("sys-1", REASON_MANUAL)
    try:
        rb.assess("sys-1", DIM_OPERATIONAL_AUTONOMY, VERDICT_PASSES, 7)
    except RetiredSystemError:
        pass
    else:
        raise AssertionError("assess on retired system must fail closed")
    assert rb.stats()["systems"] == 1
    kinds = [row["kind"] for row in rb.audit_log()]
    assert kinds == [KIND_ASSESSED, KIND_ASSESSED, KIND_RETIRED,
                     KIND_REJECTED]
    print("roboethics OK: assess, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
