"""Human oversight: human-in-the-loop / human-on-the-loop decision ledger, Simulated.

Research note: EU AI Act Art. 14 (Human oversight) requires high-risk AI
systems to be designed for effective human oversight during the period of
use: natural persons must be able to understand the system, be aware of the
tendency to over-rely on its output, intervene in or stop the system
("stop button"), and override its decisions. What matters here is the
*decision ledger*: which cases were placed under which oversight mode,
what the human reviewer declared, and whether a human override was booked -
defensible bookkeeping, not proof of actual human control.

This module owns the assign -> review -> override lifecycle:

* **assign()** - book one declared oversight assignment (pinned oversight
  mode vocabulary); reviewer identity and task payload travel as digest
  pins only; duplicates refused.
* **review()** - book one declared human review outcome (minted ``rev-N``
  ids; pinned outcome vocabulary) against an assigned case; one review per
  case; booked as data, never proof a human understood the system.
* **override()** - book one declared human override of the system decision
  (minted ``ovr-N`` ids; pinned direction vocabulary); requires a prior
  review; books the *decision*, never proof the machine was stopped.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``human-oversight.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module summons no human, shows no interface, and stops
no system. A booked ``approved`` means "the host declared a reviewer
approved", never "a person actually read this". Reviewer names, notes, task
contents, and any raw personal information never enter records or cross
the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
HUMAN_OVERSIGHT_VERSION = "human-oversight.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.human-oversight.v1"

#: Pinned human-oversight mode vocabulary (EU AI Act Art. 14-shaped).
MODES = (
    "human-in-the-loop",
    "human-on-the-loop",
    "human-in-command",
    "post-hoc-review",
)

#: Pinned review outcome vocabulary, booked as data.
OUTCOMES = (
    "approved",
    "rejected",
    "escalated",
    "amended",
)

#: Pinned override direction vocabulary (the human's declared decision).
OVERRIDE_DIRECTIONS = (
    "approve",
    "reject",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assigned",
    "reviewed",
    "overridden",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "reviewer",
        "reviewer_id",
        "reviewer_name",
        "name",
        "email",
        "phone",
        "note",
        "notes",
        "comment",
        "comments",
        "rationale",
        "reason",
        "justification",
        "task",
        "content",
        "text",
        "payload",
        "raw",
        "secret",
        "key",
        "personal_information",
        "pii",
        "data",
        "detail",
        "details",
        "description",
        "transcript",
        "prompt",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HumanOversightError(Exception):
    """Base error for human-oversight ledger misuse."""


class BadIdError(HumanOversightError):
    """Malformed case, review, or override id."""


class DuplicateCaseError(HumanOversightError):
    """Case already assigned."""


class UnknownCaseError(HumanOversightError):
    """Case not assigned."""


class BadModeError(HumanOversightError):
    """Unknown oversight mode."""


class BadOutcomeError(HumanOversightError):
    """Unknown review outcome."""


class BadDirectionError(HumanOversightError):
    """Unknown override direction."""


class BadDigestError(HumanOversightError):
    """Malformed digest pin."""


class AlreadyReviewedError(HumanOversightError):
    """Case already has a booked review."""


class AlreadyOverriddenError(HumanOversightError):
    """Case already has a booked override."""


class NoReviewError(HumanOversightError):
    """Override booked without a prior review."""


class SeqOrderError(HumanOversightError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(HumanOversightError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssignmentRecord:
    case_id: str
    oversight_mode: str
    reviewer_digest: str
    task_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "case_id": self.case_id,
            "oversight_mode": self.oversight_mode,
            "reviewer_digest": self.reviewer_digest,
            "task_digest": self.task_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "case_id": self.case_id,
                "oversight_mode": self.oversight_mode,
                "reviewer_digest": self.reviewer_digest,
                "task_digest": self.task_digest,
            }
        )


@dataclass(frozen=True)
class ReviewRecord:
    review_id: str
    case_id: str
    outcome: str
    reviewer_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "review_id": self.review_id,
            "case_id": self.case_id,
            "outcome": self.outcome,
            "reviewer_digest": self.reviewer_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "review_id": self.review_id,
                "case_id": self.case_id,
                "outcome": self.outcome,
                "reviewer_digest": self.reviewer_digest,
            }
        )


@dataclass(frozen=True)
class OverrideRecord:
    override_id: str
    case_id: str
    direction: str
    review_id: str
    reason_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "override_id": self.override_id,
            "case_id": self.case_id,
            "direction": self.direction,
            "review_id": self.review_id,
            "reason_digest": self.reason_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "override_id": self.override_id,
                "case_id": self.case_id,
                "direction": self.direction,
                "review_id": self.review_id,
                "reason_digest": self.reason_digest,
            }
        )


@dataclass(frozen=True)
class CaseStatus:
    case_id: str
    oversight_mode: str
    has_review: bool
    review_outcome: str
    has_override: bool
    override_direction: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "case_id": self.case_id,
            "oversight_mode": self.oversight_mode,
            "has_review": self.has_review,
            "review_outcome": self.review_outcome,
            "has_override": self.has_override,
            "override_direction": self.override_direction,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "case_id": self.case_id,
                "oversight_mode": self.oversight_mode,
                "has_review": self.has_review,
                "review_outcome": self.review_outcome,
                "has_override": self.has_override,
                "override_direction": self.override_direction,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def human_oversight_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the oversight ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class HumanOversight:
    """Human-oversight decision ledger, Simulated.

    ``assign()`` / ``review()`` / ``override()`` mutate the ledger and
    consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assignments: Dict[str, AssignmentRecord] = {}
        self._reviews: Dict[str, ReviewRecord] = {}
        self._overrides: Dict[str, OverrideRecord] = {}
        self._rev_counter = 0
        self._ovr_counter = 0
        self._audit: List[Dict[str, object]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        """Shape-validate a caller seq (bool/float/str refused)."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")
        return seq

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} after {self._seq}"
            )
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: HumanOversightError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            human_oversight_audit_event(
                "rejected",
                seq_v,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _emit(self, audit_kind: str, seq_v: int, **details: Any) -> None:
        self._audit.append(
            human_oversight_audit_event(audit_kind, seq_v, **details)
        )

    # -- mutations --------------------------------------------------------

    def assign(
        self,
        case_id: str,
        oversight_mode: str,
        seq: int,
        reviewer_digest: str = "",
        task_digest: str = "",
    ) -> AssignmentRecord:
        """Book one declared oversight assignment for a case."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                cid = _require_id(case_id, "case_id")
                if cid in self._assignments:
                    raise DuplicateCaseError(f"case already assigned: {cid!r}")
                if not isinstance(oversight_mode, str) or oversight_mode not in MODES:
                    raise BadModeError(
                        f"oversight_mode must be one of {sorted(MODES)}"
                    )
                rev_pin = _require_digest(reviewer_digest, "reviewer_digest")
                task_pin = _require_digest(task_digest, "task_digest")
                rec = AssignmentRecord(
                    case_id=cid,
                    oversight_mode=oversight_mode,
                    reviewer_digest=rev_pin,
                    task_digest=task_pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "case_id": cid,
                            "oversight_mode": oversight_mode,
                            "reviewer_digest": rev_pin,
                            "task_digest": task_pin,
                        }
                    ),
                )
                self._assignments[cid] = rec
                self._emit(
                    "assigned",
                    seq_v,
                    case_id=cid,
                    oversight_mode=oversight_mode,
                )
                return rec
            except HumanOversightError as exc:
                self._burn(seq_v, "assign", exc)
                raise

    def review(
        self,
        case_id: str,
        seq: int,
        outcome: str = "approved",
        reviewer_digest: str = "",
    ) -> ReviewRecord:
        """Book one declared human review outcome for an assigned case."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                cid = _require_id(case_id, "case_id")
                if cid not in self._assignments:
                    raise UnknownCaseError(f"case not assigned: {cid!r}")
                if cid in self._reviews:
                    raise AlreadyReviewedError(
                        f"case already reviewed: {cid!r}"
                    )
                if not isinstance(outcome, str) or outcome not in OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(OUTCOMES)}"
                    )
                rev_pin = _require_digest(reviewer_digest, "reviewer_digest")
                self._rev_counter += 1
                rid = f"rev-{self._rev_counter}"
                rec = ReviewRecord(
                    review_id=rid,
                    case_id=cid,
                    outcome=outcome,
                    reviewer_digest=rev_pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "review_id": rid,
                            "case_id": cid,
                            "outcome": outcome,
                            "reviewer_digest": rev_pin,
                        }
                    ),
                )
                self._reviews[cid] = rec
                self._emit(
                    "reviewed",
                    seq_v,
                    review_id=rid,
                    case_id=cid,
                    outcome=outcome,
                )
                return rec
            except HumanOversightError as exc:
                self._burn(seq_v, "review", exc)
                raise

    def override(
        self,
        case_id: str,
        seq: int,
        direction: str = "approve",
        reason_digest: str = "",
    ) -> OverrideRecord:
        """Book one declared human override of the system decision."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                cid = _require_id(case_id, "case_id")
                if cid not in self._assignments:
                    raise UnknownCaseError(f"case not assigned: {cid!r}")
                review_rec = self._reviews.get(cid)
                if review_rec is None:
                    raise NoReviewError(
                        f"override requires a booked review for: {cid!r}"
                    )
                if cid in self._overrides:
                    raise AlreadyOverriddenError(
                        f"case already overridden: {cid!r}"
                    )
                if (
                    not isinstance(direction, str)
                    or direction not in OVERRIDE_DIRECTIONS
                ):
                    raise BadDirectionError(
                        f"direction must be one of {sorted(OVERRIDE_DIRECTIONS)}"
                    )
                reason_pin = _require_digest(reason_digest, "reason_digest")
                self._ovr_counter += 1
                oid = f"ovr-{self._ovr_counter}"
                rec = OverrideRecord(
                    override_id=oid,
                    case_id=cid,
                    direction=direction,
                    review_id=review_rec.review_id,
                    reason_digest=reason_pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "override_id": oid,
                            "case_id": cid,
                            "direction": direction,
                            "review_id": review_rec.review_id,
                            "reason_digest": reason_pin,
                        }
                    ),
                )
                self._overrides[cid] = rec
                self._emit(
                    "overridden",
                    seq_v,
                    override_id=oid,
                    case_id=cid,
                    direction=direction,
                )
                return rec
            except HumanOversightError as exc:
                self._burn(seq_v, "override", exc)
                raise

    # -- pure-read views --------------------------------------------------

    def assignment_record(self, case_id: str, seq: int) -> AssignmentRecord:
        """Return one assignment record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            cid = _require_id(case_id, "case_id")
            if cid not in self._assignments:
                raise UnknownCaseError(f"case not assigned: {cid!r}")
            return self._assignments[cid]

    def review_record(self, case_id: str, seq: int) -> ReviewRecord:
        """Return one review record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            cid = _require_id(case_id, "case_id")
            if cid not in self._reviews:
                raise NoReviewError(f"no review booked for: {cid!r}")
            return self._reviews[cid]

    def override_record(self, case_id: str, seq: int) -> OverrideRecord:
        """Return one override record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            cid = _require_id(case_id, "case_id")
            if cid not in self._overrides:
                raise UnknownCaseError(f"no override booked for: {cid!r}")
            return self._overrides[cid]

    def case_ids(self, seq: int) -> Tuple[str, ...]:
        """All assigned case ids in assignment order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._assignments.keys())

    def reviewed_ids(self, seq: int) -> Tuple[str, ...]:
        """Case ids with a booked review."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._reviews.keys())

    def overridden_ids(self, seq: int) -> Tuple[str, ...]:
        """Case ids with a booked override."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._overrides.keys())

    def status(self, case_id: str, seq: int) -> CaseStatus:
        """Derive a case status snapshot (pure read, digest-pinned)."""
        with self._lock:
            self._check_seq(seq)
            cid = _require_id(case_id, "case_id")
            assignment = self._assignments.get(cid)
            if assignment is None:
                raise UnknownCaseError(f"case not assigned: {cid!r}")
            review_rec = self._reviews.get(cid)
            override_rec = self._overrides.get(cid)
            outcome = review_rec.outcome if review_rec is not None else ""
            direction = override_rec.direction if override_rec is not None else ""
            integrity = assignment.verify() and (
                review_rec.verify() if review_rec is not None else True
            ) and (override_rec.verify() if override_rec is not None else True)
            report = CaseStatus(
                case_id=cid,
                oversight_mode=assignment.oversight_mode,
                has_review=review_rec is not None,
                review_outcome=outcome,
                has_override=override_rec is not None,
                override_direction=direction,
                integrity_ok=integrity,
                digest="",
            )
            # Mint the digest over the derived payload (frozen: rebuild).
            return CaseStatus(
                case_id=cid,
                oversight_mode=report.oversight_mode,
                has_review=report.has_review,
                review_outcome=report.review_outcome,
                has_override=report.has_override,
                override_direction=report.override_direction,
                integrity_ok=report.integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "case_id": cid,
                        "oversight_mode": report.oversight_mode,
                        "has_review": report.has_review,
                        "review_outcome": report.review_outcome,
                        "has_override": report.has_override,
                        "override_direction": report.override_direction,
                        "integrity_ok": report.integrity_ok,
                    }
                ),
            )

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "cases": len(self._assignments),
                "reviews": len(self._reviews),
                "overrides": len(self._overrides),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    h = HumanOversight()
    a = h.assign(
        "case-1",
        "human-in-the-loop",
        1,
        reviewer_digest="sha256:" + "ab" * 32,
        task_digest="sha256:" + "cd" * 32,
    )
    assert a.verify()
    r = h.review(
        "case-1",
        2,
        outcome="approved",
        reviewer_digest="sha256:" + "ab" * 32,
    )
    assert r.verify()
    o = h.override(
        "case-1",
        3,
        direction="approve",
        reason_digest="sha256:" + "ef" * 32,
    )
    assert o.verify()
    st = h.status("case-1", 4)
    assert st.verify()
    assert st.has_review and st.has_override
    assert h.stats(5) == {
        "cases": 1,
        "reviews": 1,
        "overrides": 1,
        "rejected": 0,
    }
    print("human-oversight OK: assign, review, override, status, pins, audit")


if __name__ == "__main__":
    main()
