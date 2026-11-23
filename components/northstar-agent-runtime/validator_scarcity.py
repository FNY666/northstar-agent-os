"""Validator scarcity detector.

Research datum: Google paused OSS VRP (vulnerability-rewards intake)
because AI-generated submissions out-produce human validation capacity.
This is a new failure class — *validator scarcity*: the queue of items
needing human review grows faster than validators can clear it, until the
backlog itself becomes unprocessable and the intake channel has to close.

This module is a *detector + policy hook*, not a queuing system. It tracks
a submission queue against validator capacity and fires when the backlog
crosses the scarcity threshold, so the host can auto-escalate (add
reviewers, raise the triage bar) or pause intake (stop accepting new
submissions) before the queue becomes unprocessable.

House style: frozen dataclasses, no wall-clock, deterministic,
fail-closed, stdlib only, standalone-importable.

Threat model (explicit):
- In scope: backlog growth vs fixed validator capacity; graduated
  response (escalate at 5x, pause intake at 10x); intake gating while
  paused; per-submission audit trail of the scarcity decision.
- Out of scope: *why* submissions spiked (spam vs legitimate surge —
  the triage layer decides); validator scheduling/routing (the host's
  job); cross-restart persistence of the queue (caller's job, e.g.
  ``audit_chain.DurableAuditWriter``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Optional

#: Version pin for auditability.
VALIDATOR_SCARCITY_VERSION = "validator-scarcity.v1"

#: Schema pin stamped on audit records.
SCHEMA_PIN = "northstar.validator-scarcity.v1"

#: Scarcity fires when pending submissions exceed capacity * this factor.
SCARCITY_FACTOR = 10

#: Escalation fires earlier, when pending exceeds capacity * this factor.
ESCALATION_FACTOR = 5


class ScarcityError(ValueError):
    """Raised for malformed validator-scarcity inputs (fail-closed)."""


class IntakePaused(ScarcityError):
    """Raised when a submission arrives while intake is paused."""


class ScarcityAction(str, Enum):
    """Recommended host action for a scarcity assessment."""

    NONE = "none"
    ESCALATE = "escalate"
    PAUSE_INTAKE = "pause_intake"


@dataclass(frozen=True)
class ValidatorCapacity:
    """Human review capacity, in reviews per day.

    The "day" is the caller's accounting window — the module itself is
    wall-clock-free; the host maps its own day boundary (or any fixed
    window) onto the seqs it passes to the queue. What matters is that
    capacity and queue depth are measured in the same window.
    """

    max_reviews_per_day: int

    def __post_init__(self) -> None:
        if isinstance(self.max_reviews_per_day, bool) or not isinstance(
            self.max_reviews_per_day, int
        ):
            raise ScarcityError("max_reviews_per_day must be an int")
        if self.max_reviews_per_day <= 0:
            raise ScarcityError("max_reviews_per_day must be positive")

    def scarcity_threshold(self) -> int:
        """Pending count above which scarcity fires."""
        return self.max_reviews_per_day * SCARCITY_FACTOR

    def escalation_threshold(self) -> int:
        """Pending count above which escalation is recommended."""
        return self.max_reviews_per_day * ESCALATION_FACTOR


@dataclass(frozen=True)
class Submission:
    """One item awaiting human validation."""

    submission_id: str
    submitted_seq: int
    priority: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.submission_id, str) or not self.submission_id:
            raise ScarcityError("submission_id must be a non-empty string")
        if isinstance(self.submitted_seq, bool) or not isinstance(
            self.submitted_seq, int
        ):
            raise ScarcityError("submitted_seq must be an int")
        if self.submitted_seq < 0:
            raise ScarcityError("submitted_seq must be non-negative")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int):
            raise ScarcityError("priority must be an int")


@dataclass(frozen=True)
class ScarcityAssessment:
    """Frozen record of one scarcity evaluation."""

    scarce: bool
    pending: int
    capacity_per_day: int
    recommended_action: ScarcityAction
    evaluated_seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": VALIDATOR_SCARCITY_VERSION,
            "scarce": self.scarce,
            "pending": self.pending,
            "capacity_per_day": self.capacity_per_day,
            "recommended_action": self.recommended_action.value,
            "evaluated_seq": self.evaluated_seq,
        }


class SubmissionQueue:
    """Tracks pending validations against validator capacity.

    Intake gating: while paused (via :meth:`pause_intake`, or
    automatically by :meth:`apply_assessment`), :meth:`submit` raises
    :class:`IntakePaused` instead of accepting new work — fail-closed,
    so a runaway submission spike cannot deepen an already-scarce queue.
    """

    def __init__(self) -> None:
        self._pending: dict[str, Submission] = {}
        self._intake_open = True
        self._paused_seq: Optional[int] = None

    def __len__(self) -> int:
        return len(self._pending)

    def __contains__(self, submission_id: str) -> bool:
        return submission_id in self._pending

    def __iter__(self) -> Iterator[Submission]:
        # Deterministic order: submission seq, then id.
        return iter(
            sorted(self._pending.values(), key=lambda s: (s.submitted_seq, s.submission_id))
        )

    @property
    def pending(self) -> int:
        """Number of submissions awaiting validation."""
        return len(self._pending)

    @property
    def intake_open(self) -> bool:
        return self._intake_open

    def submit(self, submission: Submission) -> Submission:
        """Accept a submission for validation.

        Raises :class:`IntakePaused` while intake is paused (fail-closed).
        Raises :class:`ScarcityError` on duplicate ids.
        """
        if not isinstance(submission, Submission):
            raise ScarcityError("submission must be a Submission")
        if not self._intake_open:
            raise IntakePaused(
                f"intake paused at seq {self._paused_seq}; "
                f"submission {submission.submission_id} refused"
            )
        if submission.submission_id in self._pending:
            raise ScarcityError(
                f"duplicate submission_id: {submission.submission_id}"
            )
        self._pending[submission.submission_id] = submission
        return submission

    def complete_review(self, submission_id: str) -> Submission:
        """Mark a submission reviewed; removes it from the pending set."""
        if not isinstance(submission_id, str) or not submission_id:
            raise ScarcityError("submission_id must be a non-empty string")
        try:
            return self._pending.pop(submission_id)
        except KeyError:
            raise ScarcityError(f"unknown submission_id: {submission_id}") from None

    def pause_intake(self, seq: int) -> None:
        """Stop accepting new submissions (fail-closed). Idempotent."""
        _check_seq(seq)
        self._intake_open = False
        self._paused_seq = seq

    def resume_intake(self, seq: int) -> None:
        """Re-open intake. Idempotent."""
        _check_seq(seq)
        self._intake_open = True
        self._paused_seq = None

    def apply_assessment(self, assessment: ScarcityAssessment, seq: int) -> ScarcityAction:
        """Apply a scarcity assessment's recommendation to the queue.

        ``PAUSE_INTAKE`` pauses intake; anything else leaves the current
        intake state untouched (escalation is the host's job — more
        reviewers, higher triage bar — not the queue's).
        Returns the action that was applied.
        """
        if not isinstance(assessment, ScarcityAssessment):
            raise ScarcityError("assessment must be a ScarcityAssessment")
        _check_seq(seq)
        if assessment.recommended_action is ScarcityAction.PAUSE_INTAKE:
            self.pause_intake(seq)
        return assessment.recommended_action


def _check_seq(seq: int) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ScarcityError("seq must be an int")
    if seq < 0:
        raise ScarcityError("seq must be non-negative")


def detect_scarcity(queue: SubmissionQueue, capacity: ValidatorCapacity) -> bool:
    """True when the backlog exceeds capacity * SCARCITY_FACTOR (10x).

    Fail-closed on malformed inputs (raises, never returns False for a
    queue it cannot read).
    """
    if not isinstance(queue, SubmissionQueue):
        raise ScarcityError("queue must be a SubmissionQueue")
    if not isinstance(capacity, ValidatorCapacity):
        raise ScarcityError("capacity must be a ValidatorCapacity")
    return queue.pending > capacity.scarcity_threshold()


def assess_scarcity(
    queue: SubmissionQueue, capacity: ValidatorCapacity, seq: int
) -> ScarcityAssessment:
    """Graduated scarcity assessment: none / escalate / pause_intake.

    - pending > 10x capacity → scarce, PAUSE_INTAKE
    - pending > 5x capacity → not scarce yet, ESCALATE
    - otherwise → NONE

    Thresholds are strict (``>``): exactly at the threshold is not
    scarce — the boundary belongs to the calmer side.
    """
    if not isinstance(queue, SubmissionQueue):
        raise ScarcityError("queue must be a SubmissionQueue")
    if not isinstance(capacity, ValidatorCapacity):
        raise ScarcityError("capacity must be a ValidatorCapacity")
    _check_seq(seq)
    pending = queue.pending
    if pending > capacity.scarcity_threshold():
        action = ScarcityAction.PAUSE_INTAKE
        scarce = True
    elif pending > capacity.escalation_threshold():
        action = ScarcityAction.ESCALATE
        scarce = False
    else:
        action = ScarcityAction.NONE
        scarce = False
    return ScarcityAssessment(
        scarce=scarce,
        pending=pending,
        capacity_per_day=capacity.max_reviews_per_day,
        recommended_action=action,
        evaluated_seq=seq,
    )


def scarcity_audit_event(assessment: ScarcityAssessment, seq: int) -> dict:
    """Audit-shaped record for the ``audit.ndjson/1`` envelope."""
    if not isinstance(assessment, ScarcityAssessment):
        raise ScarcityError("assessment must be a ScarcityAssessment")
    _check_seq(seq)
    record = assessment.as_dict()
    record["audit_seq"] = seq
    return record


def main() -> None:
    cap = ValidatorCapacity(max_reviews_per_day=10)
    q = SubmissionQueue()
    for i in range(7):
        q.submit(Submission(f"sub-{i}", submitted_seq=i))
    a = assess_scarcity(q, cap, seq=7)
    assert a.recommended_action is ScarcityAction.NONE and not a.scarce
    for i in range(7, 60):
        q.submit(Submission(f"sub-{i}", submitted_seq=i))
    a = assess_scarcity(q, cap, seq=60)
    assert a.recommended_action is ScarcityAction.ESCALATE and not a.scarce
    for i in range(60, 101):
        q.submit(Submission(f"sub-{i}", submitted_seq=i))
    assert detect_scarcity(q, cap)
    a = assess_scarcity(q, cap, seq=101)
    assert a.scarce and a.recommended_action is ScarcityAction.PAUSE_INTAKE
    q.apply_assessment(a, seq=101)
    assert not q.intake_open
    print("validator-scarcity OK: escalate at 5x, pause at 10x")


if __name__ == "__main__":
    main()
