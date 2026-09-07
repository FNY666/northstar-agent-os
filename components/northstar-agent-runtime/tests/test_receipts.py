"""Capability lease lifecycle and signed action receipt tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from loop import AgentRuntime, RuntimeConfig
from permissions import PermissionConfig, PermissionEngine, PermissionRequestContext
from providers.scripted import ScriptedProvider
from receipts import (
    ActionReceipt,
    ApprovalLease,
    ApprovalLeaseLedger,
    ReceiptError,
    capability_for,
)


class LeaseLifecycleTests(unittest.TestCase):
    def lease(self, **overrides):
        values = {
            "lease_id": "lease-001",
            "session_id": "session-001",
            "workspace": "/workspace/one",
            "capabilities": ("workspace.write",),
            "issued_at": 100,
            "expires_at": 200,
            "max_uses": 2,
        }
        values.update(overrides)
        return ApprovalLease(**values)

    def test_capability_mapping_is_stable_and_not_tool_name_authorization(self):
        self.assertEqual(capability_for("edit", "Write"), "workspace.write")
        self.assertEqual(capability_for("exec", "Bash"), "process.exec")
        self.assertEqual(capability_for("other", "mcp__server__tool"), "tool.mcp.server.tool")

    def test_lease_consumes_at_most_max_uses(self):
        ledger = ApprovalLeaseLedger()
        ledger.add(self.lease())
        first = ledger.consume(session_id="session-001", workspace="/workspace/one", capability="workspace.write", now=101)
        second = ledger.consume(session_id="session-001", workspace="/workspace/one", capability="workspace.write", now=102)
        third = ledger.consume(session_id="session-001", workspace="/workspace/one", capability="workspace.write", now=103)
        self.assertEqual(first.uses, 1)
        self.assertEqual(second.uses, 2)
        self.assertIsNone(third)

    def test_revoke_removes_a_lease_before_it_can_be_consumed(self):
        ledger = ApprovalLeaseLedger()
        ledger.add(self.lease())
        self.assertTrue(ledger.revoke("lease-001"))
        self.assertFalse(ledger.revoke("lease-001"))
        self.assertIsNone(ledger.get("lease-001"))

    def test_expiry_and_scope_are_denials_without_consumption(self):
        ledger = ApprovalLeaseLedger()
        ledger.add(self.lease(max_uses=1))
        self.assertIsNone(ledger.consume(session_id="other", workspace="/workspace/one", capability="workspace.write", now=101))
        self.assertIsNone(ledger.consume(session_id="session-001", workspace="/workspace/two", capability="workspace.write", now=101))
        self.assertIsNone(ledger.consume(session_id="session-001", workspace="/workspace/one", capability="workspace.write", now=200))
        self.assertEqual(ledger.get("lease-001").uses, 0)

    def test_engine_checks_lease_before_falling_back_to_mode(self):
        ledger = ApprovalLeaseLedger()
        ledger.add(self.lease(max_uses=1))
        engine = PermissionEngine(PermissionConfig(mode="default", approval_leases=ledger, clock=lambda: 101))
        context = PermissionRequestContext(session_id="session-001", workspace="/workspace/one")
        first = engine.evaluate("Write", kind="edit", context=context, payload={"path": "a"})
        second = engine.evaluate("Write", kind="edit", context=context, payload={"path": "b"})
        self.assertTrue(first.allowed)
        self.assertEqual(first.source, "approval_lease")
        self.assertEqual(first.lease_id, "lease-001")
        self.assertFalse(second.allowed)
        self.assertEqual(second.source, "mode")

    def test_callback_can_issue_a_lease_and_the_runtime_never_trusts_a_malformed_one(self):
        ledger = ApprovalLeaseLedger()
        engine = PermissionEngine(PermissionConfig(
            mode="default",
            approval_leases=ledger,
            clock=lambda: 101,
            can_use_tool=lambda name, payload, context: {"allowed": True, "lease": self.lease().as_dict()},
        ))
        context = PermissionRequestContext(session_id="session-001", workspace="/workspace/one")
        decision = engine.evaluate("Write", kind="edit", context=context)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "approval_lease")
        self.assertEqual(ledger.get("lease-001").uses, 1)

        malformed = PermissionEngine(PermissionConfig(
            mode="default",
            approval_leases=ApprovalLeaseLedger(),
            clock=lambda: 101,
            can_use_tool=lambda *args: {"allowed": True, "lease": {"lease_id": "bad"}},
        ))
        refused = malformed.evaluate("Write", kind="edit", context=context)
        self.assertFalse(refused.allowed)
        self.assertEqual(refused.source, "approval_lease")


class ReceiptTests(unittest.TestCase):
    SECRET = b"receipt-secret-012345"

    def receipt(self):
        return ActionReceipt.new(
            session_id="session-001",
            action_id="call-001",
            tool="Write",
            capability="workspace.write",
            status="completed",
            issued_at=100,
            completed_at=101,
            input_value={"path": "a", "content": "x"},
            output_value="written",
            workspace_before="sha256:" + "0" * 64,
            workspace_after="sha256:" + "1" * 64,
            lease_id="lease-001",
        )

    def test_signed_receipt_round_trips_and_detects_tampering(self):
        signed = self.receipt().sign(self.SECRET)
        self.assertTrue(signed.verify(self.SECRET))
        loaded = ActionReceipt.from_dict(signed.to_dict())
        self.assertTrue(loaded.verify(self.SECRET))
        changed = dict(signed.to_dict())
        changed["status"] = "failed"
        self.assertFalse(ActionReceipt.from_dict({**changed, "signature": signed.signature}).verify(self.SECRET))
        self.assertFalse(signed.verify(b"wrong-secret-012345"))

    def test_unsigned_receipt_is_explicitly_not_verifiable(self):
        receipt = self.receipt()
        self.assertIsNone(receipt.signature)
        self.assertFalse(receipt.verify(self.SECRET))
        self.assertEqual(receipt.to_contract_receipt()["schema_version"], "northstar.receipt.v1")
        self.assertEqual(receipt.to_contract_receipt()["status"], "ok")

    def test_unknown_and_extra_fields_are_rejected(self):
        with self.assertRaises(ReceiptError):
            ActionReceipt.from_dict({**self.receipt().to_dict(), "surprise": True})
        with self.assertRaises(ReceiptError):
            ApprovalLease.from_dict({**self.receipt().to_dict()})


class RuntimeReceiptIntegrationTests(unittest.TestCase):
    def test_runtime_emits_signed_receipt_and_persists_only_the_signed_form(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            session_dir = Path(directory) / "sessions"
            provider = ScriptedProvider([
                {"tool": {"name": "Write", "input": {"path": "note.txt", "content": "ok"}}},
                {"text": "finished"},
            ])
            lease = ApprovalLease(
                "lease-001", "session-001", str(workspace.resolve()), ("workspace.write",), 100, 200, 1
            )
            runtime = AgentRuntime(
                provider=provider,
                config=RuntimeConfig(workspace=str(workspace), session_id="session-001"),
                approval_leases=[lease],
                receipt_secret=b"receipt-secret-012345",
                clock=lambda: 101,
                sessions=__import__("sessions").SessionStore(session_dir, session_id="session-001"),
            )
            report = runtime.run_collect("write the file")
            self.assertEqual(report.subtype, "success")
            self.assertEqual(len(report.receipts), 1)
            receipt = report.receipts[0]
            self.assertTrue(receipt.verify(b"receipt-secret-012345"))
            self.assertEqual(report.tool_calls[0].lease_id, "lease-001")
            records, _ = runtime.sessions.read()
            action_records = [record for record in records if record.get("subtype") == "action_receipt"]
            self.assertEqual(len(action_records), 1)
            self.assertEqual(action_records[0]["receipt"]["signature"], receipt.signature)
            self.assertEqual((workspace / "note.txt").read_text(), "ok")


if __name__ == "__main__":
    unittest.main()
