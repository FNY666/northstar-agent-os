"""SLA-bound approval queue for abstain-to-human escalation.

P0 wiring: ``decision model -> abstain -> approval SLA queue -> signed
receipt``. When the agent abstains (it cannot decide on its own), the
action is parked here for a human approver. Every request carries an
SLA deadline; when the deadline passes with no decision, the request
**expires and fails closed** -- silence is never consent, and an
expired request can never become approved.

No wall clock anywhere: time is caller-supplied integer sequence
numbers (``requested_seq`` / ``sla_deadline_seq`` / ``current_seq``),
so the queue is deterministic and testable. The ``sla_seconds``
parameter on :meth:`ApprovalQueue.enqueue` is expressed in
sequence-number ticks for the same reason -- the name is kept for API
compatibility with the P0 spec, but it is a duration in ticks, not in
seconds.

Hard doctrine (enforced, not aspirational):

- an expired request fails closed: ``poll`` returns ``"expired"`` and
  the action must not run;
- expiry is sticky: once expired, a request never leaves ``expired``;
- ``decide`` refuses non-pending requests: no approving or denying an
  already-expired (or already-decided) request;
- expiry never auto-approves: the only exits from ``pending`` are an
  explicit human ``decide`` or expiry to ``expired``;
- unknown request ids raise ``KeyError`` -- a lookup miss is a bug,
  not a silent denial.

Honest scope: this is the intake-and-deadline layer. It does not
authenticate the decider, it does not sign receipts (that is the next
P0 hop), and it does not make humans faster -- the SLA is the
*system's* response to silence, not a promise that an approver is
available.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Iterator

#: Version pin for this module's record shape.
APPROVAL_SLA_VERSION = "approval-sla.v1"

#: Request lifecycle states.
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_EXPIRED = "expired"

_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_DENIED, STATUS_EXPIRED)

#: Terminal states: no further transition is possible.
_TERMINAL = frozenset({STATUS_APPROVED, STATUS_DENIED, STATUS_EXPIRED})


def _check_seq(value: object, name: str) -> int:
    """Validate a sequence number: int, not bool, non-negative."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_text(value: object, name: str) -> str:
    """Validate a required text field: non-empty str."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


@dataclass(frozen=True)
class ApprovalRequest:
    """One approval request parked for a human decision.

    ``id`` is minted by the queue. ``requested_seq`` is the sequence
    number at enqueue time; ``sla_deadline_seq`` is the last sequence
    number at which a decision is still timely -- a poll with
    ``current_seq > sla_deadline_seq`` marks the request ``expired``.
    ``status`` is one of ``pending`` / ``approved`` / ``denied`` /
    ``expired``. ``decided_by`` / ``decided_seq`` are set only once a
    human decides.
    """

    id: str
    action: str
    reason: str
    requested_seq: int
    sla_deadline_seq: int
    status: str = STATUS_PENDING
    decided_by: str | None = None
    decided_seq: int | None = None

    def __post_init__(self) -> None:
        _check_text(self.id, "id")
        _check_text(self.action, "action")
        _check_text(self.reason, "reason")
        _check_seq(self.requested_seq, "requested_seq")
        _check_seq(self.sla_deadline_seq, "sla_deadline_seq")
        if self.sla_deadline_seq < self.requested_seq:
            raise ValueError(
                "sla_deadline_seq must be >= requested_seq "
                f"({self.sla_deadline_seq} < {self.requested_seq})"
            )
        if self.status not in _STATUSES:
            raise ValueError(f"unknown status {self.status!r}")
        if self.status == STATUS_PENDING and (
            self.decided_by is not None or self.decided_seq is not None
        ):
            raise ValueError("pending request must not carry decision fields")
        if self.status in (STATUS_APPROVED, STATUS_DENIED):
            if self.decided_by is None or self.decided_seq is None:
                raise ValueError(
                    f"{self.status} request must carry decided_by and decided_seq"
                )
            _check_text(self.decided_by, "decided_by")
            _check_seq(self.decided_seq, "decided_seq")


class ApprovalQueue:
    """SLA-bound intake queue for abstain-to-human escalation.

    The queue itself keeps no clock: every method that needs "now"
    takes it as an explicit ``current_seq`` argument.
    """

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

    def __len__(self) -> int:
        return len(self._requests)

    def __contains__(self, request_id: object) -> bool:
        return request_id in self._requests

    def __iter__(self) -> Iterator[ApprovalRequest]:
        return iter(self._requests.values())

    def enqueue(
        self,
        action: str,
        reason: str,
        sla_seconds: int,
        current_seq: int,
    ) -> str:
        """Park an action for human approval.

        ``sla_seconds`` is the SLA expressed in sequence-number ticks
        (no wall clock in this module): the request expires once a
        poll observes ``current_seq > requested_seq + sla_seconds``.
        Returns the minted request id.
        """
        _check_text(action, "action")
        _check_text(reason, "reason")
        _check_seq(current_seq, "current_seq")
        if isinstance(sla_seconds, bool) or not isinstance(sla_seconds, int):
            raise TypeError(
                f"sla_seconds must be an int, got {type(sla_seconds).__name__}"
            )
        if sla_seconds <= 0:
            raise ValueError(f"sla_seconds must be positive, got {sla_seconds}")
        request_id = f"apr-{uuid.uuid4().hex[:16]}"
        request = ApprovalRequest(
            id=request_id,
            action=action,
            reason=reason,
            requested_seq=current_seq,
            sla_deadline_seq=current_seq + sla_seconds,
        )
        self._requests[request_id] = request
        return request_id

    def get(self, request_id: str) -> ApprovalRequest:
        """Return the stored record. Raises ``KeyError`` if unknown."""
        try:
            return self._requests[request_id]
        except KeyError:
            raise KeyError(f"unknown approval request {request_id!r}") from None

    def poll(self, request_id: str, current_seq: int) -> str:
        """Observe a request's status at ``current_seq``.

        Returns ``pending``, ``approved``, ``denied``, or ``expired``.
        If the request is still pending and ``current_seq`` is past its
        SLA deadline, the request is marked ``expired`` (sticky) and
        ``"expired"`` is returned -- fail closed.
        """
        _check_seq(current_seq, "current_seq")
        request = self.get(request_id)
        if request.status == STATUS_PENDING and current_seq > request.sla_deadline_seq:
            expired = ApprovalRequest(
                id=request.id,
                action=request.action,
                reason=request.reason,
                requested_seq=request.requested_seq,
                sla_deadline_seq=request.sla_deadline_seq,
                status=STATUS_EXPIRED,
            )
            self._requests[request_id] = expired
            return STATUS_EXPIRED
        return request.status

    def decide(self, request_id: str, approved: bool, decider: str) -> ApprovalRequest:
        """Record a human decision. Only pending requests can be decided.

        Returns the updated record. Raises ``ValueError`` if the
        request is already approved, denied, or expired -- expiry is
        terminal and never converts into an approval.
        """
        if not isinstance(approved, bool):
            raise TypeError(
                f"approved must be a bool, got {type(approved).__name__}"
            )
        _check_text(decider, "decider")
        request = self.get(request_id)
        if request.status != STATUS_PENDING:
            raise ValueError(
                f"cannot decide request {request_id!r}: already {request.status}"
            )
        decided = ApprovalRequest(
            id=request.id,
            action=request.action,
            reason=request.reason,
            requested_seq=request.requested_seq,
            sla_deadline_seq=request.sla_deadline_seq,
            status=STATUS_APPROVED if approved else STATUS_DENIED,
            decided_by=decider,
            decided_seq=request.sla_deadline_seq,
        )
        self._requests[request_id] = decided
        return decided

    def pending(self) -> list[ApprovalRequest]:
        """Requests still awaiting a decision (not yet expired)."""
        return [r for r in self._requests.values() if r.status == STATUS_PENDING]

    def expired(self) -> list[ApprovalRequest]:
        """Requests whose SLA lapsed with no decision (fail closed)."""
        return [r for r in self._requests.values() if r.status == STATUS_EXPIRED]

    def decided(self) -> list[ApprovalRequest]:
        """Requests with a recorded human decision."""
        return [
            r
            for r in self._requests.values()
            if r.status in (STATUS_APPROVED, STATUS_DENIED)
        ]


def main() -> None:
    queue = ApprovalQueue()
    rid = queue.enqueue("rm -rf /tmp/cache", "abstain: destructive", 10, current_seq=100)
    assert queue.poll(rid, 105) == STATUS_PENDING
    queue.decide(rid, True, "op-1")
    assert queue.poll(rid, 106) == STATUS_APPROVED
    rid2 = queue.enqueue("drop table", "abstain: irreversible", 5, current_seq=200)
    assert queue.poll(rid2, 206) == STATUS_EXPIRED
    print("approval-sla OK: enqueue/poll/decide/expire")


if __name__ == "__main__":
    main()
