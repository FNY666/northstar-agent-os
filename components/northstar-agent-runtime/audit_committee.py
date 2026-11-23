"""AuditCommittee: independent audit-committee governance bookkeeping.

Research note: the IIA (Institute of Internal Auditors) Three Lines
Model and the corporate audit-committee charters (Sarbanes-Oxley /
NYSE listing standards) put the audit committee between management
and the external auditor: it reviews internal-control findings,
certifies the reported opinion, and escalates unresolved concerns to
the board or regulator. This module is the *ledger* layer for that
governance practice:

* **review()** books one declared audit review against a pinned
  review id; the reviewed subject (a report, control, or transaction
  set) is pinned by digest only -- raw subject material never enters
  a record. Duplicate review ids are refused; ids are never recycled.
* **certify()** books one declared committee opinion for a review
  over the pinned audit-opinion vocabulary (``clean`` / ``qualified``
  / ``adverse`` / ``disclaimer``), terminal and exactly once per
  review; the verdict is *data*, never proof of correctness.
  Supporting findings travel as digest pins only.
* **escalate()** books one declared escalation of a review to a
  pinned escalation level (``management`` / ``board`` / ``regulator``
  / ``independent-investigator``), forming an escalation chain -- a
  review may be escalated more than once. The escalation rationale
  travels as a digest pin only.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding,
fail-closed taxonomy, stdlib-only with the standard
``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* reviews, opinions, and
escalations; it cannot prove a subject was actually reviewed, that
an opinion is correct, or that an escalation reached anyone. Raw
subject material, finding text, and rationale text never enter
records and never cross the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
AUDIT_COMMITTEE_VERSION = "audit-committee.v1"

#: Schema pin carried by records and audit events.
AUDIT_COMMITTEE_SCHEMA = "northstar.audit-committee.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_REVIEW_OPENED = "audit-committee.review-opened"
KIND_CERTIFIED = "audit-committee.certified"
KIND_ESCALATED = "audit-committee.escalated"
KIND_REJECTED = "audit-committee.rejected"
_KINDS = frozenset(
    {KIND_REVIEW_OPENED, KIND_CERTIFIED, KIND_ESCALATED, KIND_REJECTED}
)

#: Pinned audit-opinion vocabulary for certifications.
VERDICT_CLEAN = "clean"
VERDICT_QUALIFIED = "qualified"
VERDICT_ADVERSE = "adverse"
VERDICT_DISCLAIMER = "disclaimer"
_VERDICTS = frozenset(
    {
        VERDICT_CLEAN,
        VERDICT_QUALIFIED,
        VERDICT_ADVERSE,
        VERDICT_DISCLAIMER,
    }
)

#: Pinned escalation-level vocabulary.
LEVEL_MANAGEMENT = "management"
LEVEL_BOARD = "board"
LEVEL_REGULATOR = "regulator"
LEVEL_INDEPENDENT_INVESTIGATOR = "independent-investigator"
_LEVELS = frozenset(
    {
        LEVEL_MANAGEMENT,
        LEVEL_BOARD,
        LEVEL_REGULATOR,
        LEVEL_INDEPENDENT_INVESTIGATOR,
    }
)

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class AuditCommitteeError(Exception):
    """Base class for all audit-committee errors."""


class BadReviewError(AuditCommitteeError):
    """review_id is not a usable non-empty str."""


class DuplicateReviewError(AuditCommitteeError):
    """review_id was already booked; ids are never recycled."""


class UnknownReviewError(AuditCommitteeError):
    """review_id names no review this ledger ever saw."""


class BadDigestError(AuditCommitteeError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadVerdictError(AuditCommitteeError):
    """verdict is not in the pinned audit-opinion vocabulary."""


class AlreadyCertifiedError(AuditCommitteeError):
    """The review already carries a booked opinion; certification is terminal."""


class BadLevelError(AuditCommitteeError):
    """Escalation level is not in the pinned vocabulary."""


class SeqOrderError(AuditCommitteeError):
    """seq is not a strictly-increasing int."""


class AuditKindError(AuditCommitteeError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadReviewError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadReviewError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadReviewError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_digest(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_digests(values: Any, what: str) -> Tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise BadDigestError(f"{what} must be a list/tuple of digests")
    out = []
    for i, v in enumerate(values):
        out.append(_check_digest(v, f"{what}[{i}]"))
    if len(set(out)) != len(out):
        raise BadDigestError(f"{what} contains duplicate digests")
    return tuple(out)


def _check_verdict(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadVerdictError(f"verdict must be a str, got {type(value).__name__}")
    if value not in _VERDICTS:
        raise BadVerdictError(f"verdict {value!r} not in pinned opinion vocabulary")
    return value


def _check_level(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadLevelError(f"level must be a str, got {type(value).__name__}")
    if value not in _LEVELS:
        raise BadLevelError(f"level {value!r} not in pinned escalation vocabulary")
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
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise AuditCommitteeError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise AuditCommitteeError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise AuditCommitteeError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewRecord:
    """One declared audit review; the reviewed subject is digest-pinned only."""

    review_id: str
    subject_digest: str
    digest: str
    seq: int
    schema: str = AUDIT_COMMITTEE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.review_id, self.subject_digest),
            "review",
        )


@dataclass(frozen=True)
class CertificationRecord:
    """One declared committee opinion for a review; terminal, booked exactly once."""

    certification_id: str
    review_id: str
    verdict: str
    finding_digests: Tuple[str, ...]
    digest: str
    seq: int
    schema: str = AUDIT_COMMITTEE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.certification_id,
                self.review_id,
                self.verdict,
                tuple(self.finding_digests),
            ),
            "certification",
        )


@dataclass(frozen=True)
class EscalationRecord:
    """One declared escalation of a review to a pinned level (an escalation chain step)."""

    escalation_id: str
    review_id: str
    level: str
    rationale_digest: str
    digest: str
    seq: int
    schema: str = AUDIT_COMMITTEE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.escalation_id,
                self.review_id,
                self.level,
                self.rationale_digest,
            ),
            "escalation",
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def audit_committee_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw subject/finding/rationale text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "subject",
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
        "finding",
        "findings",
        "rationale",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "audit-committee",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# AuditCommittee ledger
# ---------------------------------------------------------------------------


class AuditCommittee:
    """Audit-committee governance bookkeeping ledger: review, certify, escalate."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # review_id -> ReviewRecord (ordered)
        self._reviews: Dict[str, ReviewRecord] = {}
        # review_id -> CertificationRecord (at most one)
        self._certifications: Dict[str, CertificationRecord] = {}
        # escalation_id -> EscalationRecord (ordered)
        self._escalations: Dict[str, EscalationRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(audit_committee_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: AuditCommitteeError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def review(self, review_id: str, subject_digest: str, seq: int) -> ReviewRecord:
        """Book a declared audit review. The reviewed subject is pinned by digest only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                review_id = _check_id(review_id, "review_id")
                subject_digest = _check_digest(subject_digest, "subject_digest")
            except AuditCommitteeError as exc:
                self._fail(seq, exc, review_id=str(review_id))
            if review_id in self._reviews:
                self._fail(
                    seq,
                    DuplicateReviewError(f"review already booked: {review_id!r}"),
                    review_id=review_id,
                )
            record = ReviewRecord(
                review_id=review_id,
                subject_digest=subject_digest,
                digest=_digest_pin((review_id, subject_digest), "review"),
                seq=seq,
            )
            self._reviews[review_id] = record
            self._emit(
                KIND_REVIEW_OPENED,
                seq,
                review_id=review_id,
                subject_digest=subject_digest,
                record_digest=record.digest,
            )
            return record

    def certify(
        self,
        review_id: str,
        verdict: str,
        seq: int,
        finding_digests: Tuple[str, ...] = (),
    ) -> CertificationRecord:
        """Book the committee's opinion for a review. Terminal: exactly once per review.

        The verdict is *data* (clean / qualified / adverse / disclaimer),
        never proof that the opinion is correct.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                review_id = _check_id(review_id, "review_id")
                verdict = _check_verdict(verdict)
                finding_digests = _check_digests(finding_digests, "finding_digests")
            except AuditCommitteeError as exc:
                self._fail(seq, exc, review_id=str(review_id))
            if review_id not in self._reviews:
                self._fail(
                    seq,
                    UnknownReviewError(f"unknown review: {review_id!r}"),
                    review_id=review_id,
                )
            if review_id in self._certifications:
                self._fail(
                    seq,
                    AlreadyCertifiedError(f"review already certified: {review_id!r}"),
                    review_id=review_id,
                )
            certification_id = f"cert-{len(self._certifications) + 1}"
            record = CertificationRecord(
                certification_id=certification_id,
                review_id=review_id,
                verdict=verdict,
                finding_digests=finding_digests,
                digest=_digest_pin(
                    (certification_id, review_id, verdict, finding_digests),
                    "certification",
                ),
                seq=seq,
            )
            self._certifications[review_id] = record
            self._emit(
                KIND_CERTIFIED,
                seq,
                review_id=review_id,
                certification_id=certification_id,
                verdict=verdict,
                finding_digests=finding_digests,
                record_digest=record.digest,
            )
            return record

    def escalate(
        self,
        review_id: str,
        level: str,
        seq: int,
        rationale_digest: str = "",
    ) -> EscalationRecord:
        """Book a declared escalation of a review to a pinned level.

        A review may be escalated more than once (an escalation chain);
        each decision is a new ``EscalationRecord``. The rationale is
        pinned by digest only.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                review_id = _check_id(review_id, "review_id")
                level = _check_level(level)
                if rationale_digest != "":
                    rationale_digest = _check_digest(rationale_digest, "rationale_digest")
                elif not isinstance(rationale_digest, str):
                    raise BadDigestError("rationale_digest must be a str")
            except AuditCommitteeError as exc:
                self._fail(seq, exc, review_id=str(review_id))
            if review_id not in self._reviews:
                self._fail(
                    seq,
                    UnknownReviewError(f"unknown review: {review_id!r}"),
                    review_id=review_id,
                )
            escalation_id = f"esc-{len(self._escalations) + 1}"
            record = EscalationRecord(
                escalation_id=escalation_id,
                review_id=review_id,
                level=level,
                rationale_digest=rationale_digest,
                digest=_digest_pin(
                    (escalation_id, review_id, level, rationale_digest),
                    "escalation",
                ),
                seq=seq,
            )
            self._escalations[escalation_id] = record
            self._emit(
                KIND_ESCALATED,
                seq,
                review_id=review_id,
                escalation_id=escalation_id,
                level=level,
                rationale_digest=rationale_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def review_record(self, review_id: str, seq: int) -> Optional[ReviewRecord]:
        """Pure read: the booked review record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._reviews.get(review_id)

    def review_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of booked reviews, in booking order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._reviews)

    def certification(self, review_id: str, seq: int) -> Optional[CertificationRecord]:
        """Pure read: the booked opinion for a review, or None when uncertified."""
        _check_seq(seq)
        with self._lock:
            if review_id not in self._reviews:
                raise UnknownReviewError(f"unknown review: {review_id!r}")
            return self._certifications.get(review_id)

    def is_certified(self, review_id: str, seq: int) -> bool:
        """Pure read: whether the review already carries a booked opinion."""
        _check_seq(seq)
        with self._lock:
            if review_id not in self._reviews:
                raise UnknownReviewError(f"unknown review: {review_id!r}")
            return review_id in self._certifications

    def escalations_for(self, review_id: str, seq: int) -> Tuple[EscalationRecord, ...]:
        """Pure read: escalations booked for a review, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(e for e in self._escalations.values() if e.review_id == review_id)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "reviews": len(self._reviews),
                "certified": len(self._certifications),
                "escalations": len(self._escalations),
                "open": len(self._reviews) - len(self._certifications),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: review, certify, escalate, audit."""
    ledger = AuditCommittee()
    rev = ledger.review("rev-2026-q3", "sha256:" + "a" * 64, 1)
    assert rev.verify()
    # duplicate review ids are refused
    try:
        ledger.review("rev-2026-q3", "sha256:" + "a" * 64, 2)
    except DuplicateReviewError:
        pass
    else:
        raise AssertionError("duplicate review must be refused")
    cert = ledger.certify(
        "rev-2026-q3",
        "qualified",
        3,
        finding_digests=("sha256:" + "f" * 64,),
    )
    assert cert.verify()
    assert cert.certification_id == "cert-1"
    # certification is terminal: a second opinion is refused
    try:
        ledger.certify("rev-2026-q3", "clean", 4)
    except AlreadyCertifiedError:
        pass
    else:
        raise AssertionError("re-certification must be refused")
    esc = ledger.escalate(
        "rev-2026-q3", "board", 5, rationale_digest="sha256:" + "b" * 64
    )
    assert esc.verify()
    assert esc.escalation_id == "esc-1"
    # escalation chain: a second escalation on the same review is allowed
    esc2 = ledger.escalate("rev-2026-q3", "regulator", 6)
    assert esc2.verify() and esc2.escalation_id == "esc-2"
    assert ledger.is_certified("rev-2026-q3", 6)
    assert len(ledger.escalations_for("rev-2026-q3", 6)) == 2
    stats = ledger.stats(6)
    assert stats == {
        "reviews": 1,
        "certified": 1,
        "escalations": 2,
        "open": 0,
        "last_seq": 6,
    }
    print("audit-committee OK: review, certify, escalate, pins, audit")


if __name__ == "__main__":
    main()
