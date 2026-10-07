"""Targeted tests for mcp_approval_combo: MCP tool calls through approval."""
import sys
import unittest
from pathlib import Path

# Standalone import: load sibling modules without a package install.
_RUNTIME = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_RUNTIME))

import mcp_approval_combo as mac
from mcp_approval_combo import (
    MCP_APPROVAL_COMBO_VERSION,
    SCHEMA_PIN,
    GateDecision,
    MCPApprovalGate,
)
from mcp_drift_monitor import snapshot_tools
from approval_chain import ApprovalChain


def _tools(extra=None):
    base = [
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
    if extra:
        base.extend(extra)
    return base


def _gate(tools=None):
    tools = _tools() if tools is None else tools
    baseline = snapshot_tools("demo", tools)
    chain = ApprovalChain(approver_secret=bytes(range(32)))
    return MCPApprovalGate(server="demo", baseline=baseline, chain=chain), chain, tools


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MCP_APPROVAL_COMBO_VERSION, "mcp-approval-combo.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.mcp-approval-combo.v1")


class TestConstructor(unittest.TestCase):
    def test_rejects_empty_server(self):
        baseline = snapshot_tools("demo", _tools())
        chain = ApprovalChain(approver_secret=bytes(range(32)))
        with self.assertRaises(ValueError):
            MCPApprovalGate(server=" ", baseline=baseline, chain=chain)

    def test_rejects_bad_baseline(self):
        chain = ApprovalChain(approver_secret=bytes(range(32)))
        with self.assertRaises(TypeError):
            MCPApprovalGate(server="demo", baseline="nope", chain=chain)

    def test_rejects_bad_chain(self):
        baseline = snapshot_tools("demo", _tools())
        with self.assertRaises(TypeError):
            MCPApprovalGate(server="demo", baseline=baseline, chain="nope")


class TestGatePaths(unittest.TestCase):
    def test_low_risk_clean_no_receipt_allows(self):
        gate, _, tools = _gate()
        d = gate.check(tool_name="web_search", tools_list=tools, current_seq=5)
        self.assertEqual(d.verdict, "allow")
        self.assertFalse(d.receipt_required)
        self.assertEqual(d.drift_decision, "allow")

    def test_high_risk_without_receipt_denies(self):
        gate, _, tools = _gate()
        d = gate.check(tool_name="exec_shell", tools_list=tools, current_seq=5)
        self.assertEqual(d.verdict, "deny")
        self.assertTrue(d.receipt_required)
        self.assertFalse(d.receipt_ok)
        self.assertEqual(d.reason, "receipt-required")

    def test_high_risk_with_valid_receipt_allows(self):
        gate, chain, tools = _gate()
        rid = gate.request_tool_approval("exec_shell", "ops", 5)
        chain.approve(rid, "human:op", 5)
        receipt = chain.collect_receipt(rid)
        d = gate.check(
            tool_name="exec_shell", tools_list=tools, receipt=receipt,
            current_seq=5,
        )
        self.assertEqual(d.verdict, "allow")
        self.assertTrue(d.receipt_ok)

    def test_receipt_for_wrong_tool_denies(self):
        gate, chain, tools = _gate()
        rid = gate.request_tool_approval("web_search", "ops", 5)
        chain.approve(rid, "human:op", 5)
        receipt = chain.collect_receipt(rid)
        d = gate.check(
            tool_name="exec_shell", tools_list=tools, receipt=receipt,
            current_seq=5,
        )
        self.assertEqual(d.verdict, "deny")
        self.assertIn("chain-deny", d.reason)

    def test_drift_deny_beats_receipt(self):
        gate, chain, tools = _gate()
        rid = gate.request_tool_approval("exec_shell", "ops", 5)
        chain.approve(rid, "human:op", 5)
        receipt = chain.collect_receipt(rid)
        drifted = [
            {
                "name": "exec_shell",
                "description": "Run a shell command, now with network",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cmd": {"type": "string"}},
                },
            },
            tools[0],
            tools[1],
        ]
        d = gate.check(
            tool_name="exec_shell", tools_list=drifted, receipt=receipt,
            current_seq=5,
        )
        self.assertEqual(d.verdict, "deny")
        self.assertEqual(d.drift_decision, "deny")
        self.assertIn("drift-deny", d.reason)

    def test_non_sensitive_drift_still_allows(self):
        gate, _, tools = _gate()
        drifted = list(tools)
        drifted[1] = dict(tools[1], description="Search the web, v2 copy")
        d = gate.check(tool_name="web_search", tools_list=drifted, current_seq=5)
        self.assertEqual(d.verdict, "allow")

    def test_removed_tool_denies(self):
        gate, _, tools = _gate()
        gone = [tools[0], tools[2]]  # web_search removed (non-sensitive)
        d = gate.check(tool_name="web_search", tools_list=gone, current_seq=5)
        self.assertEqual(d.verdict, "deny")
        self.assertEqual(d.reason, "tool-not-advertised")

    def test_check_simple_returns_verdict_string(self):
        gate, _, tools = _gate()
        self.assertEqual(
            gate.check_simple(tool_name="web_search", tools_list=tools,
                              current_seq=5),
            "allow",
        )
        self.assertEqual(
            gate.check_simple(tool_name="exec_shell", tools_list=tools,
                              current_seq=5),
            "deny",
        )

    def test_action_type_forced_to_tool_name(self):
        gate, chain, tools = _gate()
        rid = gate.request_tool_approval("exec_shell", "ops", 5)
        chain.approve(rid, "human:op", 5)
        receipt = chain.collect_receipt(rid)
        # Caller-supplied action_type is overridden; binding uses the tool.
        d = gate.check(
            tool_name="exec_shell", tools_list=tools, receipt=receipt,
            action={"action_type": "something-else", "note": "x"},
            current_seq=5,
        )
        self.assertEqual(d.verdict, "allow")


class TestDecisionRecord(unittest.TestCase):
    def test_decision_frozen_and_shaped(self):
        d = GateDecision(
            verdict="allow", tool_name="web_search", drift_decision="allow",
            receipt_required=False, receipt_ok=False, reason="ok",
        )
        with self.assertRaises(Exception):
            d.verdict = "deny"  # frozen
        asd = d.as_dict()
        self.assertEqual(asd["schema"], SCHEMA_PIN)
        self.assertEqual(asd["tool_name"], "web_search")

    def test_decision_rejects_bad_verdict(self):
        with self.assertRaises(ValueError):
            GateDecision(
                verdict="maybe", tool_name="t", drift_decision="allow",
                receipt_required=False, receipt_ok=False, reason="x",
            )


class TestInputValidation(unittest.TestCase):
    def test_rejects_empty_tool_name(self):
        gate, _, tools = _gate()
        with self.assertRaises(ValueError):
            gate.check(tool_name="", tools_list=tools)

    def test_rejects_non_sequence_tools_list(self):
        gate, _, tools = _gate()
        with self.assertRaises(TypeError):
            gate.check(tool_name="web_search", tools_list="not-a-list")

    def test_rejects_bad_tools_entry(self):
        gate, _, tools = _gate()
        with self.assertRaises(TypeError):
            gate.check(tool_name="web_search", tools_list=[{"name": "x"}, 42])

    def test_rejects_negative_seq(self):
        gate, _, tools = _gate()
        with self.assertRaises(ValueError):
            gate.check(tool_name="web_search", tools_list=tools, current_seq=-1)

    def test_rejects_bad_action(self):
        gate, _, tools = _gate()
        with self.assertRaises(TypeError):
            gate.check(tool_name="web_search", tools_list=tools, action=42)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        mac.main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
