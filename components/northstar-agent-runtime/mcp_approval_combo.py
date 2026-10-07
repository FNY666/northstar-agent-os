"""MCP tool-call approval gate: drift tripwire + signed-receipt authorization.

An MCP server's ``tools/list`` response is host-reported and can change
between calls; a signed receipt proves a human approved an action. This
module composes the two into one per-call decision point for MCP tool use:

* :mod:`mcp_drift_monitor` — the surface-integrity tripwire. The fresh
  ``tools/list`` response is snapshotted and diffed against the pinned
  admission baseline on every call.
* :mod:`approval_chain` — the human-authorization chain (SLA queue ->
  signed receipt -> edge gate). Security-sensitive tools require a
  signed receipt; the receipt must bind the exact tool name.

Check order, fail closed:

1. **Drift.** ``check_tools_list`` diffs the fresh response against the
   baseline. A ``deny`` verdict means the surface moved — no receipt can
   override it, because the approval was issued for the old surface.
2. **Advertisement.** The requested tool must be present in the *fresh*
   snapshot. A tool removed from the surface cannot be called even when
   the drift was non-sensitive.
3. **Authorization.** :func:`is_sensitive_tool` decides whether a signed
   receipt is required. With a receipt, the approval chain verifies it,
   checks the action binding, enforces one-receipt-one-execution, and
   runs the edge gate.

The gate never fetches ``tools/list`` itself: the host supplies the fresh
response on every call, keeping this module offline and deterministic.
No wall-clock is read; sequence numbers are caller-supplied.

Honest scope: this gates *calls* on a host-reported surface. It cannot
see a server that lies consistently (same lie in baseline and fresh
response passes the drift check), and it cannot prove the tool did what
it claimed — that is the audit layer's job. A clean ``allow`` means
"surface unchanged, tool advertised, authorization satisfied", never
"the tool is trustworthy".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from mcp_drift_monitor import (
    McpToolSnapshot,
    check_tools_list,
    is_sensitive_tool,
    snapshot_tools,
)
from approval_chain import ApprovalChain

#: Version pin for this module.
MCP_APPROVAL_COMBO_VERSION = "mcp-approval-combo.v1"
#: Schema pin carried on decision records.
SCHEMA_PIN = "northstar.mcp-approval-combo.v1"

_VERDICTS = frozenset({"allow", "deny"})


def _check_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty str")
    return value


def _check_seq(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative int")
    return value


@dataclass(frozen=True)
class GateDecision:
    """Full record of one MCP tool-call gate verdict."""

    verdict: str  # "allow" or "deny"
    tool_name: str
    drift_decision: str  # "allow" or "deny", from the drift tripwire
    receipt_required: bool
    receipt_ok: bool
    reason: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.verdict not in _VERDICTS:
            raise ValueError("verdict must be 'allow' or 'deny'")
        if self.drift_decision not in _VERDICTS:
            raise ValueError("drift_decision must be 'allow' or 'deny'")

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "tool_name": self.tool_name,
            "drift_decision": self.drift_decision,
            "receipt_required": self.receipt_required,
            "receipt_ok": self.receipt_ok,
            "reason": self.reason,
            "schema": self.schema,
        }


class MCPApprovalGate:
    """Per-server gate composing the MCP drift tripwire and the approval chain.

    ``server`` names the MCP server this gate guards. ``baseline`` is the
    admission-time :class:`McpToolSnapshot`. ``chain`` is the shared
    :class:`ApprovalChain` the host wires for human authorization.
    """

    def __init__(
        self,
        *,
        server: str,
        baseline: McpToolSnapshot,
        chain: ApprovalChain,
    ) -> None:
        self._server = _check_text("server", server)
        if not isinstance(baseline, McpToolSnapshot):
            raise TypeError("baseline must be a McpToolSnapshot")
        if not isinstance(chain, ApprovalChain):
            raise TypeError("chain must be an ApprovalChain")
        self._baseline = baseline
        self._chain = chain

    # -- hop 0: park a tool call for human approval ------------------------

    def request_tool_approval(
        self,
        tool_name: str,
        reason: str,
        current_seq: int,
        sla_ticks: int | None = None,
    ) -> str:
        """Park ``tool_name`` for human approval; returns the request id.

        The receipt is issued against the tool name itself, so the call
        must later present an action whose ``action_type`` is this name.
        """
        _check_text("tool_name", tool_name)
        return self._chain.request_approval(
            tool_name, reason, current_seq, sla_ticks=sla_ticks
        )

    # -- the gate ----------------------------------------------------------

    def check(
        self,
        *,
        tool_name: str,
        tools_list: Sequence[Mapping[str, Any]],
        action: Mapping[str, Any] | None = None,
        receipt: Any = None,
        current_seq: int = 0,
    ) -> GateDecision:
        """Gate one MCP tool call. Returns a frozen :class:`GateDecision`.

        ``tools_list`` is the fresh ``tools/list`` response the host just
        fetched. ``action`` carries optional extra fields; its
        ``action_type`` is forced to ``tool_name`` so the receipt binding
        and the edge-gate classification both see the real tool identity.
        Never raises on policy input; malformed input raises.
        """
        _check_text("tool_name", tool_name)
        _check_seq("current_seq", current_seq)
        if not isinstance(tools_list, Sequence) or isinstance(
            tools_list, (str, bytes)
        ):
            raise TypeError("tools_list must be a sequence of mappings")
        for entry in tools_list:
            if not isinstance(entry, Mapping):
                raise TypeError("tools_list entries must be mappings")
        if action is not None and not isinstance(action, Mapping):
            raise TypeError("action must be a mapping or None")
        extras = dict(action) if action is not None else {}
        # The action *is* the tool call: force the identity so neither a
        # confused caller nor a relabeled tool can dodge the binding check.
        extras["action_type"] = tool_name

        # 1. Drift tripwire: the surface must not have moved.
        assessment = check_tools_list(self._server, self._baseline, tools_list)
        if assessment.decision == "deny":
            return GateDecision(
                verdict="deny",
                tool_name=tool_name,
                drift_decision="deny",
                receipt_required=is_sensitive_tool(tool_name),
                receipt_ok=False,
                reason=f"drift-deny: {assessment.reason}",
            )

        # 2. Advertisement: the tool must exist on the current surface.
        current = snapshot_tools(self._server, tools_list)
        advertised = {pin.name for pin in current.tools}
        if tool_name not in advertised:
            return GateDecision(
                verdict="deny",
                tool_name=tool_name,
                drift_decision="allow",
                receipt_required=is_sensitive_tool(tool_name),
                receipt_ok=False,
                reason="tool-not-advertised",
            )

        # 3. Authorization: sensitive tools need a signed receipt.
        required = is_sensitive_tool(tool_name)
        if not required:
            return GateDecision(
                verdict="allow",
                tool_name=tool_name,
                drift_decision="allow",
                receipt_required=False,
                receipt_ok=False,
                reason="drift-clean, tool advertised, no receipt required",
            )
        if receipt is None:
            return GateDecision(
                verdict="deny",
                tool_name=tool_name,
                drift_decision="allow",
                receipt_required=True,
                receipt_ok=False,
                reason="receipt-required",
            )
        detailed = self._chain.execute_detailed(
            extras, receipt, current_seq=current_seq
        )
        if detailed.verdict != "allow":
            return GateDecision(
                verdict="deny",
                tool_name=tool_name,
                drift_decision="allow",
                receipt_required=True,
                receipt_ok=detailed.receipt_ok,
                reason=f"chain-deny: {detailed.reason}",
            )
        return GateDecision(
            verdict="allow",
            tool_name=tool_name,
            drift_decision="allow",
            receipt_required=True,
            receipt_ok=True,
            reason="drift-clean, tool advertised, receipt verified",
        )

    def check_simple(
        self,
        *,
        tool_name: str,
        tools_list: Sequence[Mapping[str, Any]],
        action: Mapping[str, Any] | None = None,
        receipt: Any = None,
        current_seq: int = 0,
    ) -> str:
        """Same as :meth:`check`, returning only ``"allow"`` / ``"deny"``."""
        return self.check(
            tool_name=tool_name,
            tools_list=tools_list,
            action=action,
            receipt=receipt,
            current_seq=current_seq,
        ).verdict


def main() -> None:
    """Self-check: exercise the gate end to end."""
    tools = [
        {
            "name": "read_file",
            "description": "Read a file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
        {
            "name": "web_search",
            "description": "Search the web",
            "inputSchema": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
            },
        },
        {
            "name": "exec_shell",
            "description": "Run a shell command",
            "inputSchema": {
                "type": "object",
                "properties": {"cmd": {"type": "string"}},
            },
        },
    ]
    baseline = snapshot_tools("demo", tools)
    chain = ApprovalChain(approver_secret=bytes(range(32)))
    gate = MCPApprovalGate(server="demo", baseline=baseline, chain=chain)

    # Low-risk tool, clean surface, no receipt -> allow.
    d = gate.check(tool_name="web_search", tools_list=tools, current_seq=10)
    assert d.verdict == "allow" and not d.receipt_required, d

    # High-risk tool without a receipt -> deny.
    d = gate.check(tool_name="exec_shell", tools_list=tools, current_seq=10)
    assert d.verdict == "deny" and d.reason == "receipt-required", d

    # High-risk tool with a minted receipt -> allow.
    rid = gate.request_tool_approval("exec_shell", "ops runbook", 10)
    receipt = chain.approve(rid, "human:op", 10)
    assert receipt is not None
    collected = chain.collect_receipt(rid)
    d = gate.check(
        tool_name="exec_shell",
        tools_list=tools,
        receipt=collected,
        current_seq=10,
    )
    assert d.verdict == "allow" and d.receipt_ok, d

    # Drift on a sensitive tool -> deny even with a valid receipt.
    drifted = [
        {
            "name": "exec_shell",
            "description": "Run a shell command, now with network",
            "inputSchema": {
                "type": "object",
                "properties": {"cmd": {"type": "string"}},
            },
        },
    ] + tools[:2]
    d = gate.check(
        tool_name="exec_shell",
        tools_list=drifted,
        receipt=collected,
        current_seq=10,
    )
    assert d.verdict == "deny" and d.drift_decision == "deny", d

    # Tool removed from the surface -> deny (non-sensitive removal passes
    # the drift tripwire as allow-with-log, then the advertisement check
    # catches the call itself).
    search_gone = [tools[0], tools[2]]
    d = gate.check(tool_name="web_search", tools_list=search_gone, current_seq=10)
    assert d.verdict == "deny" and d.reason == "tool-not-advertised", d

    print("mcp-approval-combo OK: allow/deny/receipt/drift/advertised paths")


if __name__ == "__main__":
    main()
