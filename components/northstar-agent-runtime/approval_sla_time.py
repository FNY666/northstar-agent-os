"""SLA-bound approval queue, wall-clock variant.

Alternative method to ``approval_sla.py`` (sequence-number based).
Same interface shape and the same hard doctrine, but deadlines are
wall-clock timestamps instead of caller-supplied sequence ticks:

- ``ApprovalRequest`` carries ``requested_at`` (float seconds since the
  epoch, as returned by :func:`time.time`) and ``timeout_seconds``.
- :meth:`ApprovalRequest.is_expired` returns True when
  ``time.time() > requested_at + timeout_seconds``.

Hard doctrine (identical to the seq-based version, enforced):

- an expired request fails closed: ``poll`` returns ``"expired"`` and
  the action must not run;
- expiry is sticky: once expired, a request never leaves ``expired``;
- ``decide`` refuses non-pending requests: no approving or denying an
  already-expired (or already-decided) request;
- expiry never auto-approves: the only exits from ``pending`` are an
  explicit human ``decide`` or expiry to ``expired``;
- unknown request ids raise ``KeyError`` -- a lookup miss is a bug,
  not a silent denial.

Interface deltas vs the seq-based ``approval_sla.ApprovalQueue``
(documented so the two can be compared method-for-method):

- ``enqueue(action, reason, timeout_seconds)`` drops ``current_seq``;
  the request time is ``time.time()`` at enqueue.
- ``poll(request_id)`` drops ``current_seq``; expiry is evaluated
  against the wall clock at poll time.
- ``decided_seq`` becomes ``decided_at`` (float timestamp of decision).

Honest scope: this is the intake-and-deadline layer, same as the seq
version. It does not authenticate the decider and does not sign
receipts. Wall-clock note: ``time.time()`` can jump backwards under
NTP adjustments, which can un-expire a request's *evaluation* (the
stored record is never mutated back -- expiry, once recorded by
``poll``, is still sticky). A ``time.monotonic()``-based variant would
be strictly more robust for SLA purposes; this module follows the
wall-clock spec deliberately so the two methods can be compared
head-to-head.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Iterator

#: Version pin for this module's record shape. Distinct from the
#: seq-based ``approval-sla.v1``: the two record shapes are not
#: interchangeable.
APPROVAL_SLA_TIME_VERSION = "approval-sla-time.v1"

#: Request lifecycle states (same vocabulary as the seq-based version).
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_EXPIRED = "expired"

_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_DENIED, STATUS_EXPIRED)

#: Terminal states: no further transition is possible.
_TERMINAL = frozenset({STATUS_APPROVED, STATUS_DENIED, STATUS_EXPIRED})


def _check_timestamp(value: object, name: str) -> float:
    """Validate a wall-clock timestamp: real number, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    value = float(value)
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_timeout(value: object, name: str) -> float:
    """Validate a timeout: real number, not bool, strictly positive."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    value = float(value)
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
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

    ``requested_at`` is the wall-clock time of enqueue
    (:func:`time.time`); ``timeout_seconds`` is the SLA duration. The
    request expires once the wall clock passes
    ``requested_at + timeout_seconds``. ``status`` is one of
    ``pending`` / ``approved`` / ``denied`` / ``expired``.
    ``decided_by`` / ``decided_at`` are set only once a human decides.
    """

    id: str
    action: str
    reason: str
    requested_at: float
    timeout_seconds: float
    status: str = STATUS_PENDING
    decided_by: str | None = None
    decided_at: float | None = None

    def __post_init__(self) -> None:
        _check_text(self.id, "id")
        _check_text(self.action, "action")
        _check_text(self.reason, "reason")
        _check_timestamp(self.requested_at, "requested_at")
        _check_timeout(self.timeout_seconds, "timeout_seconds")
        if self.status not in _STATUSES:
            raise ValueError(f"unknown status {self.status!r}")
        if self.status == STATUS_PENDING and (
            self.decided_by is not None or self.decided_at is not None
        ):
            raise ValueError("pending request must not carry decision fields")
        if self.status in (STATUS_APPROVED, STATUS_DENIED):
            if self.decided_by is None or self.decided_at is None:
                raise ValueError(
                    f"{self.status} request must carry decided_by and decided_at"
                )
            _check_text(self.decided_by, "decided_by")
            _check_timestamp(self.decided_at, "decided_at")

    @property
    def deadline(self) -> float:
        """Wall-clock instant after which the request is expired."""
        return self.requested_at + self.timeout_seconds

    def _is_expired_at(self, now: float) -> bool:
        """Expiry predicate at an explicit instant (test hook).

        Strict: exactly at the deadline the request is still pending.
        """
        return now > self.deadline

    def is_expired(self) -> bool:
        """True when the wall clock has passed the SLA deadline.

        Specified as ``time.time() > requested_at + timeout_seconds``.
        """
        return self._is_expired_at(time.time())


class ApprovalQueue:
    """SLA-bound intake queue with wall-clock deadlines.

    Method names mirror the seq-based ``approval_sla.ApprovalQueue``
    for direct comparison; the ``current_seq`` parameters are dropped
    because "now" is the wall clock.
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
        timeout_seconds: float,
    ) -> str:
        """Park an action for human approval.

        ``timeout_seconds`` is a real duration in seconds (unlike the
        seq-based version, where the parameter is sequence ticks kept
        under the same name for API compatibility). Returns the minted
        request id.
        """
        _check_text(action, "action")
        _check_text(reason, "reason")
        _check_timeout(timeout_seconds, "timeout_seconds")
        request_id = f"apr-{uuid.uuid4().hex[:16]}"
        request = ApprovalRequest(
            id=request_id,
            action=action,
            reason=reason,
            requested_at=time.time(),
            timeout_seconds=timeout_seconds,
        )
        self._requests[request_id] = request
        return request_id

    def get(self, request_id: str) -> ApprovalRequest:
        """Return the stored record. Raises ``KeyError`` if unknown."""
        try:
            return self._requests[request_id]
        except KeyError:
            raise KeyError(f"unknown approval request {request_id!r}") from None

    def poll(self, request_id: str) -> str:
        """Observe a request's status against the wall clock.

        Returns ``pending``, ``approved``, ``denied``, or ``expired``.
        If the request is still pending and the wall clock is past its
        SLA deadline, the request is marked ``expired`` (sticky) and
        ``"expired"`` is returned -- fail closed.
        """
        request = self.get(request_id)
        if request.status == STATUS_PENDING and request.is_expired():
            expired = ApprovalRequest(
                id=request.id,
                action=request.action,
                reason=request.reason,
                requested_at=request.requested_at,
                timeout_seconds=request.timeout_seconds,
                status=STATUS_EXPIRED,
            )
            self._requests[request_id] = expired
            return STATUS_EXPIRED
        return request.status

    def decide(
        self, request_id: str, approved: bool, decider: str
    ) -> ApprovalRequest:
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
        # Evaluate expiry before deciding: a request whose deadline
        # passed while nobody was watching must fail closed, not sit
        # in a decidable "pending" state.
        self.poll(request_id)
        request = self.get(request_id)
        if request.status != STATUS_PENDING:
            raise ValueError(
                f"cannot decide request {request_id!r}: already {request.status}"
            )
        decided = ApprovalRequest(
            id=request.id,
            action=request.action,
            reason=request.reason,
            requested_at=request.requested_at,
            timeout_seconds=request.timeout_seconds,
            status=STATUS_APPROVED if approved else STATUS_DENIED,
            decided_by=decider,
            decided_at=time.time(),
        )
        self._requests[request_id] = decided
        return decided

    def pending(self) -> list[ApprovalRequest]:
        """Requests still awaiting a decision (not yet observed expired)."""
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


__all__ = [
    "APPROVAL_SLA_TIME_VERSION",
    "STATUS_PENDING",
    "STATUS_APPROVED",
    "STATUS_DENIED",
    "STATUS_EXPIRED",
    "ApprovalRequest",
    "ApprovalQueue",
]


def main() -> None:
    queue = ApprovalQueue()
    rid = queue.enqueue("rm -rf /tmp/cache", "abstain: destructive", 3600.0)
    assert queue.poll(rid) == STATUS_PENDING
    queue.decide(rid, True, "op-1")
    assert queue.poll(rid) == STATUS_APPROVED
    # An already-expired request: requested long ago, short timeout.
    old = ApprovalRequest(
        id="apr-old",
        action="drop table",
        reason="abstain: irreversible",
        requested_at=time.time() - 100.0,
        timeout_seconds=10.0,
    )
    assert old.is_expired()
    queue._requests[old.id] = old
    assert queue.poll(old.id) == STATUS_EXPIRED
    print("approval-sla-time OK: enqueue/poll/decide/expire")


if __name__ == "__main__":
    main()
