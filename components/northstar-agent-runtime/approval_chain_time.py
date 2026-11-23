"""Approval chain with wall-clock SLA: SLA queue -> signed receipt -> edge gate.

Variant of ``approval_chain.py`` for human-facing deployments. The pipeline,
the hard doctrine, and the wiring are identical; the only substitution is
the approval SLA queue: this chain uses the wall-clock
``approval_sla_time.ApprovalQueue`` (deadlines in seconds) instead of the
sequence-tick ``approval_sla.ApprovalQueue``.

Pipeline this closes::

    decision model -> abstain -> approval SLA queue (wall clock)
        -> signed receipt reflux -> edge gate -> execute

1. :meth:`ApprovalChainTime.request_approval` parks an action in the
   wall-clock SLA queue (human escalation with a fail-closed deadline).
2. :meth:`ApprovalChainTime.approve` records the human decision; on
   approval it mints a signed receipt and delivers it on the reflux
   channel. The receipt's ``approved_at_seq`` is ``int(time.time())``
   (epoch seconds, caller-supplied int — the receipt format is
   clock-agnostic).
3. :meth:`ApprovalChainTime.execute_with_approval` is the decision-point
   gate: receipt signature verification, action binding, replay
   protection, then the edge gate. A valid receipt *satisfies* the edge
   gate's human requirement.

Hard doctrine (identical to the seq-based chain, enforced):

- no receipt, no execution;
- one receipt authorizes exactly one execution (replay refused);
- expiry is terminal: an SLA-expired request can never be approved;
- a receipt never widens authority: it binds the exact
  ``(request_id, action)`` pair;
- malformed input is denied, not escalated.

Interface deltas vs ``approval_chain.ApprovalChain``:

- constructor takes ``sla_timeout_seconds`` (float seconds, default 300.0)
  instead of ``sla_ticks``;
- ``request_approval(action, reason, sla_timeout_seconds=None)`` — no
  ``current_seq``; the request time is ``time.time()`` at enqueue;
- ``poll(request_id)`` — no ``current_seq``; expiry is evaluated against
  the wall clock;
- ``approve(request_id, approver, approved=True)`` — no ``current_seq``;
  the receipt's ``approved_at_seq`` is ``int(time.time())`` at approval;
- ``execute_with_approval`` / ``execute_detailed`` keep the
  ``current_seq`` hook: it exists solely for the edge gate's logical
  clock (``max_confirmation_age_seq``). The chain itself never reads
  the clock on the execute path.

Honest scope: wall-clock note from the SLA module applies here —
``time.time()`` can jump under NTP. For SLA-critical determinism use
the seq-based chain; this variant is the operator-ergonomic edge (see
the ``approval_sla_time`` vs ``approval_sla`` comparison).
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import ed25519
from approval_sla_time import ApprovalQueue, STATUS_APPROVED, STATUS_PENDING
from edge_gate import DECISION_DENY, EdgeGate
from signed_receipt_reflux import (
    RefluxChannel,
    SignedReceipt,
    issue_receipt,
    receipt_digest,
    verify_receipt,
)

#: Version pin for this integration's record shape. Deliberately distinct
#: from ``approval_chain.v1``: records are not interchangeable with the
#: seq-based chain (request ids are the same shape, deadlines are not).
APPROVAL_CHAIN_TIME_VERSION = "approval-chain-time.v1"

#: Verdict vocabulary returned by execute_with_approval / execute_detailed.
CHAIN_ALLOW = "allow"
CHAIN_DENY = "deny"


def _check_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str")
    return value


def _check_timeout(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{name} must be a positive number of seconds")
    return float(value)


def _action_string(action: Mapping[str, Any]) -> str:
    """The action string the receipt binds to: the normalized action_type."""
    raw = action.get("action_type", action.get("type", ""))
    if not isinstance(raw, str):
        return ""
    return raw.strip().lower()


@dataclass(frozen=True)
class ChainDecision:
    """Full record of one execute_with_approval verdict."""

    verdict: str
    request_id: str
    receipt_ok: bool
    action_bound: bool
    edge_verdict: str
    reason: str


class ApprovalChainTime:
    """Time-based variant of ``approval_chain.ApprovalChain``.

    ``approver_secret`` is the 32-byte Ed25519 secret used to mint
    receipts; the public key is derived from it for verification.
    ``sla_timeout_seconds`` is the default wall-clock SLA for parked
    requests. ``irreversible_allowlist`` / ``max_confirmation_age_seq``
    are passed through to the edge gate.
    """

    def __init__(
        self,
        *,
        approver_secret: bytes,
        approver_name: str = "human:approver",
        sla_timeout_seconds: float = 300.0,
        irreversible_allowlist: tuple[str, ...] = (),
        max_confirmation_age_seq: int | None = None,
    ) -> None:
        if not isinstance(approver_secret, (bytes, bytearray)) or len(approver_secret) != 32:
            raise ValueError("approver_secret must be 32 bytes")
        _check_text("approver_name", approver_name)
        timeout = _check_timeout("sla_timeout_seconds", sla_timeout_seconds)
        self._secret = bytes(approver_secret)
        self._pubkey = ed25519.public_key(self._secret)
        self._approver_name = approver_name
        self._sla_timeout = timeout
        self._queue = ApprovalQueue()
        self._channel = RefluxChannel()
        self._gate = EdgeGate(
            irreversible_allowlist=irreversible_allowlist,
            max_confirmation_age_seq=max_confirmation_age_seq,
        )
        # Receipt digests already consumed: replay protection at the chain
        # layer (the channel has pop semantics; this covers callers holding
        # the object).
        self._consumed: set[str] = set()

    # -- hop 1: park for human approval ------------------------------------

    def request_approval(
        self,
        action: str,
        reason: str,
        sla_timeout_seconds: float | None = None,
    ) -> str:
        """Park ``action`` in the wall-clock SLA queue. Returns the request id."""
        _check_text("action", action)
        _check_text("reason", reason)
        timeout = self._sla_timeout if sla_timeout_seconds is None else sla_timeout_seconds
        timeout = _check_timeout("sla_timeout_seconds", timeout)
        return self._queue.enqueue(action, reason, timeout)

    def poll(self, request_id: str) -> str:
        """Observe a parked request: pending / approved / denied / expired."""
        return self._queue.poll(request_id)

    # -- hop 2: human decides, receipt flows back --------------------------

    def approve(
        self,
        request_id: str,
        approver: str,
        approved: bool = True,
    ) -> Optional[SignedReceipt]:
        """Record the human decision; on approval mint and deliver a receipt.

        Returns the :class:`SignedReceipt`, or ``None`` when no receipt is
        issued: the request expired (fail closed), the human denied it, or
        the request was already decided. Raises ``KeyError`` for an unknown
        request id (a lookup miss is a bug, not a silent denial).
        """
        _check_text("approver", approver)
        if not isinstance(approved, bool):
            raise TypeError("approved must be a bool")
        status = self._queue.poll(request_id)
        if status != STATUS_PENDING:
            return None
        request = self._queue.get(request_id)
        decided = self._queue.decide(request_id, approved, approver)
        if decided.status != STATUS_APPROVED:
            return None
        receipt = issue_receipt(
            request_id=request.id,
            action=request.action,
            approver=approver,
            approved_at_seq=int(time.time()),
            approver_secret=self._secret,
        )
        self._channel.deliver(receipt)
        return receipt

    def collect_receipt(self, request_id: str) -> Optional[SignedReceipt]:
        """Take the delivered receipt for ``request_id`` (consumes it)."""
        return self._channel.collect(request_id)

    # -- hop 3: decision-point gate ----------------------------------------

    def execute_with_approval(
        self,
        action: Mapping[str, Any],
        receipt: Any,
        *,
        current_seq: int = 0,
    ) -> str:
        """Gate one execution: receipt verification + action binding + edge gate.

        Returns ``"allow"`` or ``"deny"``. Never raises on policy input.
        A valid receipt satisfies the edge gate's human requirement (the
        human already confirmed this exact action); anything else fails
        closed. ``current_seq`` is the edge gate's logical clock only.
        """
        return self.execute_detailed(action, receipt, current_seq=current_seq).verdict

    def execute_detailed(
        self,
        action: Any,
        receipt: Any,
        *,
        current_seq: int = 0,
    ) -> ChainDecision:
        """Same as :meth:`execute_with_approval` with the full record."""
        request_id = receipt.request_id if isinstance(receipt, SignedReceipt) else ""
        # 1. receipt must verify under the approver key.
        if not verify_receipt(receipt, self._pubkey):
            return ChainDecision(CHAIN_DENY, request_id, False, False, "", "bad-receipt")
        # 2. receipt must bind to this exact action (not a capability token).
        if not isinstance(action, Mapping):
            return ChainDecision(CHAIN_DENY, request_id, True, False, "", "malformed-action")
        expected = _action_string(action)
        if not expected or not hmac.compare_digest(
            receipt.action.encode("utf-8"), expected.encode("utf-8")
        ):
            return ChainDecision(CHAIN_DENY, request_id, True, False, "", "action-mismatch")
        # 3. one receipt, one execution: refuse replays.
        digest = receipt_digest(receipt)
        if digest in self._consumed:
            return ChainDecision(CHAIN_DENY, request_id, True, True, "", "receipt-replayed")
        # 4. edge gate: malformed is denied; a valid receipt satisfies
        #    the human requirement the gate would otherwise impose.
        edge_verdict = self._gate.check(action, {}, seq=current_seq)
        if edge_verdict == DECISION_DENY:
            return ChainDecision(CHAIN_DENY, request_id, True, True, edge_verdict, "edge-deny")
        self._consumed.add(digest)
        return ChainDecision(CHAIN_ALLOW, request_id, True, True, edge_verdict, "ok")


def main() -> None:
    chain = ApprovalChainTime(approver_secret=bytes(range(32)))
    rid = chain.request_approval("db.delete", "abstain: irreversible", 300.0)
    assert chain.poll(rid) == STATUS_PENDING
    receipt = chain.approve(rid, "human:op")
    assert receipt is not None
    assert chain.execute_with_approval({"action_type": "db.delete"}, receipt) == CHAIN_ALLOW
    # replay refused
    assert chain.execute_with_approval({"action_type": "db.delete"}, receipt) == CHAIN_DENY
    print("approval-chain-time OK: request/approve/receipt/edge/execute")


if __name__ == "__main__":
    main()
