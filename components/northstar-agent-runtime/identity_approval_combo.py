"""Identity disclosure precedes human approval.

Integration wiring: ``identity_disclosure`` + ``approval_sla``.

When an agent parks an action for human approval, the human is the
counterparty in a user-facing flow -- they are owed to know WHO is
asking before they decide. This module makes that ordering
structural, not polite:

1. :meth:`IdentityApprovalGate.request_approval` first records the
   disclosure (formats the text, appends it to the
   :class:`~identity_disclosure.DisclosureLog`), *then* enqueues the
   approval request. A request can never outlive its disclosure.
2. The queued approval reason always carries the identity line
   (``requested by <agent>, operated by <operator>``), so the
   approver sees who is asking even in the raw queue view.
3. Every request id is linked to its disclosure record digest, so an
   audit can prove the disclosure happened before the request.

Hard doctrine (enforced, not aspirational):

- no card, no request: a missing or malformed identity card refuses
  the request outright (fail closed -- a human must never approve a
  request from an undisclosed agent);
- a tampered disclosure log refuses all new requests: the gate calls
  ``verify_chain()`` before every request, and a broken chain is a
  denial, not a warning;
- the context rule is a floor: a user-facing channel discloses even
  under a NEVER deployment policy (``identity_disclosure`` doctrine);
- approval_sla doctrine is preserved: unknown request ids raise
  ``KeyError``, expiry is terminal and fails closed, expiry never
  auto-approves.

No wall clock anywhere: all sequence numbers are caller-supplied
integers, so the gate is deterministic and testable.

Honest scope: this module proves a disclosure record was produced and
linked before the approval request existed. It does not prove the
human read the disclosure or the approval reason -- delivery is the
host's job. A linked disclosure means "the counterparty was told who
is asking", never "the counterparty understood".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from approval_sla import (
    ApprovalQueue,
    ApprovalRequest,
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_PENDING,
)
from identity_disclosure import (
    DisclosureError,
    DisclosureLog,
    DisclosureRecord,
    DisclosureRequirement,
    IdentityCard,
    disclosure_decision,
)

#: Version pin for this integration's record shape.
IDENTITY_APPROVAL_VERSION = "identity-approval-combo.v1"

#: Schema pin for audit events emitted by this module.
IDENTITY_APPROVAL_SCHEMA = "northstar.identity-approval-combo.v1"


def _check_seq(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty str")
    return value.strip()


@dataclass(frozen=True)
class IdentityApproval:
    """One identity-bound approval request.

    ``request_id`` is the approval_sla queue id. ``agent_name`` and
    ``operator`` name who is asking. ``disclosed`` says whether a
    formal disclosure was recorded for this request (user-facing
    context or ALWAYS policy); ``disclosure_digest`` pins the
    :class:`DisclosureRecord` when one was made (``None`` otherwise).
    ``disclosure_text`` is the human-readable text the host presents
    (``None`` when no disclosure was required).
    """

    request_id: str
    agent_name: str
    operator: str
    context: str
    action: str
    seq: int
    disclosed: bool
    disclosure_digest: Optional[str]
    disclosure_text: Optional[str]

    def __post_init__(self) -> None:
        _check_text("request_id", self.request_id)
        _check_text("agent_name", self.agent_name)
        _check_text("operator", self.operator)
        _check_text("context", self.context)
        _check_text("action", self.action)
        _check_seq("seq", self.seq)
        if not isinstance(self.disclosed, bool):
            raise ValueError("disclosed must be a bool")
        if self.disclosed:
            _check_text("disclosure_digest", self.disclosure_digest or "")
            if self.disclosure_text is None or not self.disclosure_text.strip():
                raise ValueError("disclosed request must carry disclosure_text")
        else:
            if self.disclosure_digest is not None:
                raise ValueError("undisclosed request must not carry disclosure_digest")
            if self.disclosure_text is not None:
                raise ValueError("undisclosed request must not carry disclosure_text")

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": IDENTITY_APPROVAL_VERSION,
            "request_id": self.request_id,
            "agent_name": self.agent_name,
            "operator": self.operator,
            "context": self.context,
            "action": self.action,
            "seq": self.seq,
            "disclosed": self.disclosed,
            "disclosure_digest": self.disclosure_digest,
            "schema": IDENTITY_APPROVAL_SCHEMA,
        }


class IdentityApprovalGate:
    """Approval intake that refuses to ask an undisclosed question.

    Wraps a caller-owned :class:`ApprovalQueue` and
    :class:`DisclosureLog`; the gate never invents identities or
    approvals, it only enforces the disclosure-before-request order.
    """

    def __init__(
        self,
        log: DisclosureLog,
        queue: ApprovalQueue,
        requirement: DisclosureRequirement = DisclosureRequirement.ALWAYS,
    ) -> None:
        if not isinstance(log, DisclosureLog):
            raise DisclosureError(f"log must be a DisclosureLog, got {type(log).__name__}")
        if not isinstance(queue, ApprovalQueue):
            raise DisclosureError(f"queue must be an ApprovalQueue, got {type(queue).__name__}")
        if not isinstance(requirement, DisclosureRequirement):
            raise DisclosureError(
                f"requirement must be a DisclosureRequirement, got {requirement!r}"
            )
        self._log = log
        self._queue = queue
        self._requirement = requirement
        # request_id -> DisclosureRecord (only for requests that disclosed).
        self._links: dict[str, DisclosureRecord] = {}

    def requires_disclosure(self, context: str, *, on_request: bool = False) -> bool:
        """True when a disclosure must be recorded for ``context``."""
        return disclosure_decision(self._requirement, context, on_request=on_request)

    def request_approval(
        self,
        action: str,
        reason: str,
        card: IdentityCard,
        context: str,
        sla_seconds: int,
        current_seq: int,
        *,
        on_request: bool = False,
    ) -> IdentityApproval:
        """Disclose first, then park the action for human approval.

        ``card`` is mandatory even when no formal disclosure is
        required: the queued reason always names the requester.
        Returns the :class:`IdentityApproval` linking the request to
        its disclosure (when made).
        """
        _check_text("action", action)
        _check_text("reason", reason)
        if not isinstance(card, IdentityCard):
            raise DisclosureError(
                f"card must be an IdentityCard, got {type(card).__name__}"
            )
        _check_text("context", context)
        if isinstance(sla_seconds, bool) or not isinstance(sla_seconds, int):
            raise ValueError(f"sla_seconds must be an int, got {type(sla_seconds).__name__}")
        if sla_seconds <= 0:
            raise ValueError(f"sla_seconds must be positive, got {sla_seconds}")
        _check_seq("current_seq", current_seq)

        # Fail closed on a tampered disclosure log before anything is written.
        if not self._log.verify_chain():
            raise DisclosureError(
                "disclosure log chain is broken; refusing to request approval"
            )

        identity_line = f"requested by {card.agent_name}, operated by {card.operator}"
        queued_reason = f"[identity] {identity_line} | {reason.strip()}"

        disclosed = self.requires_disclosure(context, on_request=on_request)
        record: Optional[DisclosureRecord] = None
        text: Optional[str] = None
        if disclosed:
            record, text = self._log.disclose(card, context.strip(), seq=current_seq)

        request_id = self._queue.enqueue(
            action.strip(), queued_reason, sla_seconds, current_seq
        )
        if record is not None:
            self._links[request_id] = record

        return IdentityApproval(
            request_id=request_id,
            agent_name=card.agent_name,
            operator=card.operator,
            context=context.strip(),
            action=action.strip(),
            seq=current_seq,
            disclosed=disclosed,
            disclosure_digest=record.record_digest() if record else None,
            disclosure_text=text,
        )

    def disclosure_for(self, request_id: str) -> Optional[DisclosureRecord]:
        """The disclosure record behind ``request_id`` (``None`` if none was made)."""
        _check_text("request_id", request_id)
        return self._links.get(request_id)

    def poll(self, request_id: str, current_seq: int) -> str:
        """Observe the request's status (delegates to the SLA queue)."""
        return self._queue.poll(request_id, current_seq)

    def decide(self, request_id: str, approved: bool, decider: str) -> ApprovalRequest:
        """Record a human decision (delegates to the SLA queue)."""
        return self._queue.decide(request_id, approved, decider)

    def pending(self) -> list[ApprovalRequest]:
        return self._queue.pending()

    def expired(self) -> list[ApprovalRequest]:
        return self._queue.expired()

    def decided(self) -> list[ApprovalRequest]:
        return self._queue.decided()


def identity_approval_audit_events(
    approval: IdentityApproval,
    *,
    note: str = "",
) -> list[dict[str, Any]]:
    """Audit events for one identity-bound approval request.

    Pins the request id, who asked, whether a disclosure was recorded
    and which record digest, so the ``audit.ndjson/1`` chain anchors
    "the human was told who is asking before this request existed".
    """
    if not isinstance(approval, IdentityApproval):
        raise DisclosureError(f"needs an IdentityApproval, got {type(approval).__name__}")
    return [
        {
            "event": "identity_approval.requested",
            "request_id": approval.request_id,
            "agent_name": approval.agent_name,
            "operator": approval.operator,
            "context": approval.context,
            "action": approval.action,
            "seq": approval.seq,
            "disclosed": approval.disclosed,
            "disclosure_digest": approval.disclosure_digest,
            "identity_approval_version": IDENTITY_APPROVAL_VERSION,
            "schema": IDENTITY_APPROVAL_SCHEMA,
            "note": note,
        }
    ]


def main() -> None:
    log = DisclosureLog()
    queue = ApprovalQueue()
    gate = IdentityApprovalGate(log, queue)
    card = IdentityCard(
        agent_name="northstar-ops",
        operator="ops-team",
        capabilities_summary="run approved maintenance actions",
        limitations="cannot approve its own actions",
    )
    approval = gate.request_approval(
        "restart worker-3", "abstain: disruptive", card, "chat", 10, current_seq=100
    )
    assert approval.disclosed is True
    assert len(log) == 1
    assert len(queue) == 1
    assert gate.poll(approval.request_id, 105) == STATUS_PENDING
    assert gate.disclosure_for(approval.request_id) is not None
    gate.decide(approval.request_id, True, "op-1")
    assert gate.poll(approval.request_id, 106) == STATUS_APPROVED
    print("identity-approval-combo OK: disclose-then-request, poll, decide")


if __name__ == "__main__":
    main()


__all__ = [
    "IDENTITY_APPROVAL_VERSION",
    "IDENTITY_APPROVAL_SCHEMA",
    "IdentityApproval",
    "IdentityApprovalGate",
    "identity_approval_audit_events",
]
