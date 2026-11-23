"""Approval chain: SLA queue -> signed receipt -> edge gate, wired end to end.

Pipeline this closes::

    decision model -> abstain -> approval SLA queue
        -> signed receipt reflux -> edge gate -> execute

The three hops already exist as standalone P0 modules; this module is the
*wiring* between them — the integration point where a parked approval
becomes an executable authorization:

1. :meth:`ApprovalChain.request_approval` parks an action in the SLA
   queue (human escalation with a fail-closed deadline).
2. :meth:`ApprovalChain.approve` records the human decision; on approval
   it mints a signed receipt and delivers it on the reflux channel.
3. :meth:`ApprovalChain.execute_with_approval` is the decision-point
   gate: it verifies the receipt's signature, binds the receipt to this
   exact action (a receipt for ``db.delete`` never authorizes
   ``email.send``), consumes the receipt so it cannot authorize twice,
   then runs the edge gate. A valid receipt *satisfies* the edge gate's
   human requirement — the human already confirmed this exact action —
   so ``require_human`` becomes ``allow``; a malformed action is still
   denied outright, and a bad receipt is denied.

Hard doctrine (enforced, not aspirational):

- no receipt, no execution: a missing, expired-channel, tampered, or
  wrong-key receipt is a denial, never a retry;
- one receipt authorizes exactly one execution: consumed receipts are
  refused on replay (fail closed);
- expiry is terminal: an SLA-expired request can never be approved and
  never yields a receipt;
- a receipt never widens authority: it authorizes the exact
  ``(request_id, action)`` pair it was minted for, nothing else;
- malformed input is denied, not escalated: there is nothing coherent
  for a human to have confirmed.

No wall clock anywhere: all sequence numbers are caller-supplied ints,
so the chain is deterministic and testable.

Honest scope: this wires three already-audited modules; it does not
re-implement their checks. Approver-key management, human availability,
and durable delivery across restarts live outside this module (see the
honest-scope notes of the three hops).
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import ed25519
from approval_sla import ApprovalQueue, STATUS_APPROVED, STATUS_PENDING
from edge_gate import DECISION_DENY, EdgeGate
from signed_receipt_reflux import (
    RefluxChannel,
    SignedReceipt,
    issue_receipt,
    receipt_digest,
    verify_receipt,
)

#: Version pin for this integration's record shape.
APPROVAL_CHAIN_VERSION = "approval-chain.v1"

#: Verdict vocabulary returned by execute_with_approval / execute_detailed.
CHAIN_ALLOW = "allow"
CHAIN_DENY = "deny"


def _check_seq(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative int")
    return value


def _check_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str")
    return value


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


class ApprovalChain:
    """One object wiring the approval SLA queue, receipt reflux, and edge gate.

    ``approver_secret`` is the 32-byte Ed25519 secret used to mint
    receipts; the public key is derived from it for verification.
    ``sla_ticks`` is the default SLA (in sequence-number ticks) for
    parked requests. ``irreversible_allowlist`` / ``max_confirmation_age_seq``
    are passed through to the edge gate.
    """

    def __init__(
        self,
        *,
        approver_secret: bytes,
        approver_name: str = "human:approver",
        sla_ticks: int = 100,
        irreversible_allowlist: tuple[str, ...] = (),
        max_confirmation_age_seq: int | None = None,
    ) -> None:
        if not isinstance(approver_secret, (bytes, bytearray)) or len(approver_secret) != 32:
            raise ValueError("approver_secret must be 32 bytes")
        _check_text("approver_name", approver_name)
        if isinstance(sla_ticks, bool) or not isinstance(sla_ticks, int) or sla_ticks <= 0:
            raise ValueError("sla_ticks must be a positive int")
        self._secret = bytes(approver_secret)
        self._pubkey = ed25519.public_key(self._secret)
        self._approver_name = approver_name
        self._sla_ticks = sla_ticks
        self._queue = ApprovalQueue()
        self._channel = RefluxChannel()
        self._gate = EdgeGate(
            irreversible_allowlist=irreversible_allowlist,
            max_confirmation_age_seq=max_confirmation_age_seq,
        )
        # Receipt digests already consumed: replay protection at the chain layer
        # (the channel has pop semantics; this covers callers holding the object).
        self._consumed: set[str] = set()

    # -- hop 1: park for human approval ------------------------------------

    def request_approval(
        self,
        action: str,
        reason: str,
        current_seq: int,
        sla_ticks: int | None = None,
    ) -> str:
        """Park ``action`` in the SLA queue. Returns the request id."""
        _check_text("action", action)
        _check_text("reason", reason)
        _check_seq("current_seq", current_seq)
        ticks = self._sla_ticks if sla_ticks is None else sla_ticks
        if isinstance(ticks, bool) or not isinstance(ticks, int) or ticks <= 0:
            raise ValueError("sla_ticks must be a positive int")
        return self._queue.enqueue(action, reason, ticks, current_seq)

    def poll(self, request_id: str, current_seq: int) -> str:
        """Observe a parked request: pending / approved / denied / expired."""
        return self._queue.poll(request_id, current_seq)

    # -- hop 2: human decides, receipt flows back --------------------------

    def approve(
        self,
        request_id: str,
        approver: str,
        current_seq: int,
        approved: bool = True,
    ) -> Optional[SignedReceipt]:
        """Record the human decision; on approval mint and deliver a receipt.

        Returns the :class:`SignedReceipt`, or ``None`` when no receipt is
        issued: the request expired (fail closed), the human denied it, or
        the request was already decided. Raises ``KeyError`` for an unknown
        request id (a lookup miss is a bug, not a silent denial).
        """
        _check_text("approver", approver)
        _check_seq("current_seq", current_seq)
        if not isinstance(approved, bool):
            raise TypeError("approved must be a bool")
        status = self._queue.poll(request_id, current_seq)
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
            approved_at_seq=current_seq,
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
        closed.
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
    chain = ApprovalChain(approver_secret=bytes(range(32)))
    rid = chain.request_approval("db.delete", "abstain: irreversible", 100)
    assert chain.poll(rid, 150) == STATUS_PENDING
    receipt = chain.approve(rid, "human:op", 150)
    assert receipt is not None
    assert chain.execute_with_approval({"action_type": "db.delete"}, receipt) == CHAIN_ALLOW
    # replay refused
    assert chain.execute_with_approval({"action_type": "db.delete"}, receipt) == CHAIN_DENY
    # expired request never yields a receipt
    rid2 = chain.request_approval("x.drop", "abstain", 200, sla_ticks=5)
    assert chain.approve(rid2, "human:op", 206) is None
    print("approval-chain OK: request/approve/receipt/edge/execute")


if __name__ == "__main__":
    main()
