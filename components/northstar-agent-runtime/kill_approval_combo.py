"""Kill-switch-over-approval integration: the brake overrides the human loop.

Composes :class:`kill_switch.KillSwitch` (the host's emergency brake) with
:class:`approval_chain.ApprovalChain` (SLA queue -> signed receipt -> edge
gate) so that one invariant holds everywhere: **while the kill switch is
triggered, nothing is approved and nothing executes**.

Ordering guarantee (public API only, no private-member access):

* ``request_approval`` while triggered -> no request is parked (returns
  ``None``); the intake itself is refused.
* ``approve`` while triggered -> no receipt is minted (returns ``None``).
* ``execute_with_approval`` / ``execute_detailed`` while triggered ->
  ``"deny"`` regardless of any receipt the caller holds. A receipt minted
  *before* the trigger is still cryptographically valid; this gate refuses
  to honor it while the brake is engaged. Revocation lives at the decision
  point, which is the only place it can be enforced.
* ``emergency_stop`` -> triggers the switch, then deny-decides every
  request this gate parked that is still pending (decider
  ``"kill-switch"``). Requests already approved/denied/expired are reported
  as already closed, never re-decided.

House style: frozen dataclasses, caller-supplied int seqs (no wall-clock),
fail-closed (never raises on policy input), stdlib-only, deterministic.

Honest scope: this is a *composition*, not a new primitive. It cannot revoke
a receipt that was already consumed by an execution that happened *before*
the trigger (that execution is in the past), and it does not inspect the
physical world — ``"deny"`` means the gate refused, not that nothing moved.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from approval_chain import ApprovalChain, ChainDecision
from kill_switch import KillSwitch

KILL_APPROVAL_COMBO_VERSION = "kill-approval-combo.v1"
SCHEMA_PIN = "northstar.kill-approval-combo.v1"

_KILL_DECIDER = "kill-switch"
_DENIED_AT_DECISION = "kill-switch-triggered"


def _check_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str")
    return value


def _check_seq(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative int")
    return value


@dataclass(frozen=True)
class EmergencyStopReport:
    """Frozen record of one :meth:`KillApprovalGate.emergency_stop`."""

    schema: str
    version: str
    seq: int
    reason: str
    switch_triggered: bool
    cancelled: tuple  # request ids deny-decided by this stop
    already_closed: tuple  # request ids already terminal before this stop

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "seq": self.seq,
            "reason": self.reason,
            "switch_triggered": self.switch_triggered,
            "cancelled": list(self.cancelled),
            "already_closed": list(self.already_closed),
        }


class KillApprovalGate:
    """ApprovalChain with a kill-switch brake wired above every hop."""

    def __init__(self, kill_switch: KillSwitch, chain: ApprovalChain) -> None:
        if not isinstance(kill_switch, KillSwitch):
            raise TypeError("kill_switch must be a KillSwitch")
        if not isinstance(chain, ApprovalChain):
            raise TypeError("chain must be an ApprovalChain")
        self._switch = kill_switch
        self._chain = chain
        # Request ids this gate parked, in first-seen order. Tracked here
        # (not via chain internals) so cancellation uses only public API.
        self._request_order: list[str] = []

    # -- brake state ------------------------------------------------------

    def is_triggered(self) -> bool:
        """True while the kill switch is engaged."""
        return self._switch.is_triggered

    def check(self) -> tuple[bool, str]:
        """The switch's own gate hook: (True, "allow") or (False, reason)."""
        return self._switch.check()

    # -- hop 1: intake ------------------------------------------------------

    def request_approval(
        self,
        action: str,
        reason: str,
        current_seq: int,
        sla_ticks: int | None = None,
    ) -> Optional[str]:
        """Park ``action`` for human approval; ``None`` while triggered.

        While the kill switch is triggered no request is parked at all —
        intake is refused rather than queued behind a brake that will deny
        it. Never raises on policy input.
        """
        if self._switch.is_triggered:
            return None
        request_id = self._chain.request_approval(
            action, reason, current_seq, sla_ticks=sla_ticks
        )
        self._request_order.append(request_id)
        return request_id

    def poll(self, request_id: str, current_seq: int) -> str:
        """Observe a parked request: pending / approved / denied / expired."""
        return self._chain.poll(request_id, current_seq)

    # -- hop 2: human decision ---------------------------------------------

    def approve(
        self,
        request_id: str,
        approver: str,
        current_seq: int,
        approved: bool = True,
    ):
        """Record the human decision; ``None`` while triggered.

        While the kill switch is triggered no receipt is minted even for a
        request that was parked before the trigger. Never raises on policy
        input (unknown request ids raise KeyError, same as the chain).
        """
        if self._switch.is_triggered:
            return None
        return self._chain.approve(request_id, approver, current_seq, approved=approved)

    def collect_receipt(self, request_id: str):
        """Take the delivered receipt for ``request_id`` (consumes it)."""
        return self._chain.collect_receipt(request_id)

    # -- hop 3: decision-point gate -----------------------------------------

    def execute_with_approval(
        self,
        action: Mapping[str, Any],
        receipt: Any,
        *,
        current_seq: int = 0,
    ) -> str:
        """Gate one execution: ``"deny"`` while triggered, else the chain.

        A pre-trigger receipt does not buy execution during the trigger —
        revocation is enforced at the decision point. Never raises on policy
        input.
        """
        if self._switch.is_triggered:
            return "deny"
        return self._chain.execute_with_approval(
            action, receipt, current_seq=current_seq
        )

    def execute_detailed(
        self,
        action: Any,
        receipt: Any,
        *,
        current_seq: int = 0,
    ) -> ChainDecision:
        """Same as :meth:`execute_with_approval` with the full record."""
        if self._switch.is_triggered:
            return ChainDecision(
                verdict="deny",
                request_id="",
                receipt_ok=False,
                action_bound=False,
                edge_verdict=_DENIED_AT_DECISION,
                reason="kill switch triggered: execution refused regardless of receipt",
            )
        return self._chain.execute_detailed(action, receipt, current_seq=current_seq)

    # -- the brake ----------------------------------------------------------

    def emergency_stop(self, reason: str, seq: int) -> EmergencyStopReport:
        """Trigger the kill switch and cancel every pending approval.

        Pending requests this gate parked are deny-decided with decider
        ``"kill-switch"`` (public ``approve(..., approved=False)`` path —
        a denial is recorded, not a silent drop). Already terminal requests
        are reported as closed, never re-decided. The switch trigger is
        sticky; a second call finds nothing pending.
        """
        _check_text("reason", reason)
        _check_seq("seq", seq)
        triggered = self._switch.trigger(reason=reason, seq=seq)
        cancelled: list[str] = []
        already_closed: list[str] = []
        for request_id in self._request_order:
            status = self._chain.poll(request_id, seq)
            if status == "pending":
                # Deny-decide via the public approve path; returns None
                # because no receipt is minted for a denial.
                self._chain.approve(request_id, _KILL_DECIDER, seq, approved=False)
                cancelled.append(request_id)
            else:
                already_closed.append(request_id)
        return EmergencyStopReport(
            schema=SCHEMA_PIN,
            version=KILL_APPROVAL_COMBO_VERSION,
            seq=seq,
            reason=reason,
            switch_triggered=triggered,
            cancelled=tuple(cancelled),
            already_closed=tuple(already_closed),
        )


def main() -> None:
    """Self-check: trigger cancels pending, denies execution, intake refused."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        secret = bytes(range(32))
        gate = KillApprovalGate(
            KillSwitch(os.path.join(tmp, "ks.json")),
            ApprovalChain(approver_secret=secret),
        )
        rid = gate.request_approval("robot.arm.move", "test move", current_seq=1)
        assert rid is not None and gate.poll(rid, 1) == "pending"
        report = gate.emergency_stop("misbehaving", seq=2)
        assert report.switch_triggered and report.cancelled == (rid,)
        assert gate.poll(rid, 2) == "denied"
        assert gate.request_approval("x.y", "intake", current_seq=3) is None
        assert gate.approve(rid, "human", 3) is None
        assert gate.execute_with_approval({"action_type": "x.y"}, None) == "deny"
        decision = gate.execute_detailed({"action_type": "x.y"}, None)
        assert decision.verdict == "deny" and decision.edge_verdict == "kill-switch-triggered"
    print("kill-approval-combo OK: stop cancels pending, denies execution, refuses intake")


if __name__ == "__main__":
    main()
