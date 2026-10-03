import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from governed_memory import GovernedMemory, GovernedMemoryError  # noqa: E402
from receipt_gate import (  # noqa: E402
    RECEIPT_GATE_SCHEMA_VERSION,
    Receipt,
    ReceiptGate,
    ReceiptGateError,
    canonical_sha256_hex,
)


class ReceiptGateTest(unittest.TestCase):
    def test_emit_and_verify_roundtrip(self):
        gate = ReceiptGate()
        content = {"phase": 2, "approved": True}
        receipt = gate.emit(gate="GATE 2", content=content, issued_at=1000)
        self.assertTrue(receipt.receipt_id.startswith("gate:GATE 2:"))
        self.assertEqual(receipt.content_digest, canonical_sha256_hex(content))
        verified = gate.verify(receipt.receipt_id, content, now=1001)
        self.assertEqual(verified.receipt_id, receipt.receipt_id)

    def test_verify_fails_closed_on_content_change(self):
        gate = ReceiptGate()
        receipt = gate.emit(gate="GATE 1", content={"v": 1}, issued_at=1000)
        with self.assertRaises(ReceiptGateError):
            gate.verify(receipt.receipt_id, {"v": 2}, now=1001)
        # Receipt is now invalidated; even the original content fails.
        with self.assertRaises(ReceiptGateError):
            gate.verify(receipt.receipt_id, {"v": 1}, now=1002)
        self.assertEqual(
            gate.get(receipt.receipt_id).state, "invalidated"
        )

    def test_verify_unknown_receipt_fails_closed(self):
        gate = ReceiptGate()
        with self.assertRaises(ReceiptGateError):
            gate.verify("gate:GATE 1:deadbeef", {"v": 1}, now=1000)

    def test_revoke_requires_reason(self):
        gate = ReceiptGate()
        receipt = gate.emit(gate="GATE 0", content=[1, 2], issued_at=1000)
        with self.assertRaises(ValueError):
            gate.revoke(receipt.receipt_id, reason="", now=1001)
        gate.revoke(receipt.receipt_id, reason="change-request", now=1001)
        with self.assertRaises(ReceiptGateError):
            gate.verify(receipt.receipt_id, [1, 2], now=1002)

    def test_dependency_change_invalidates_derivatively(self):
        gate = ReceiptGate()
        upstream = {"spec": "v1"}
        upstream_digest = canonical_sha256_hex(upstream)
        receipt = gate.emit(
            gate="GATE 2",
            content={"derived": True},
            issued_at=1000,
            deps={"upstream-receipt": upstream_digest},
        )
        # Unchanged upstream verifies fine.
        gate.verify(
            receipt.receipt_id,
            {"derived": True},
            now=1001,
            dep_contents={"upstream-receipt": upstream},
        )
        # Changed upstream invalidates derivatively.
        with self.assertRaises(ReceiptGateError):
            gate.verify(
                receipt.receipt_id,
                {"derived": True},
                now=1002,
                dep_contents={"upstream-receipt": {"spec": "v2"}},
            )

    def test_receipt_serialization_roundtrip(self):
        gate = ReceiptGate()
        receipt = gate.emit(
            gate="GATE 3",
            content="final",
            role="architect",
            approved_by="human-1",
            issued_at=1000,
        )
        restored = Receipt.from_dict(receipt.to_dict())
        self.assertEqual(restored.receipt_id, receipt.receipt_id)
        self.assertEqual(restored.role, "architect")
        self.assertEqual(restored.approved_by, "human-1")

    def test_schema_version_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            Receipt.from_dict(
                {"schema_version": "bogus", "receipt_id": "x",
                 "gate": "g", "content_digest": "d"}
            )

    def test_status_lists_receipts(self):
        gate = ReceiptGate()
        gate.emit(gate="GATE 1", content=1, issued_at=1000)
        gate.emit(gate="GATE 2", content=2, issued_at=1001)
        status = gate.status()
        self.assertEqual(len(status), 2)
        self.assertTrue(
            all(s["schema_version"] == RECEIPT_GATE_SCHEMA_VERSION
                for s in status)
        )


class GovernedMemoryTest(unittest.TestCase):
    def test_write_and_read_roundtrip(self):
        mem = GovernedMemory()
        receipt = mem.write("plan", {"steps": ["a", "b"]}, issued_at=1000)
        value = mem.read("plan", receipt.receipt_id, now=1001)
        self.assertEqual(value, {"steps": ["a", "b"]})

    def test_read_with_wrong_receipt_fails_closed(self):
        mem = GovernedMemory()
        receipt = mem.write("k", "v", issued_at=1000)
        with self.assertRaises(GovernedMemoryError):
            mem.read("k", "gate:memory.write:k:deadbeef", now=1001)
        # The real receipt still works.
        self.assertEqual(mem.read("k", receipt.receipt_id, now=1001), "v")

    def test_read_missing_key_fails_closed(self):
        mem = GovernedMemory()
        with self.assertRaises(GovernedMemoryError):
            mem.read("nope", "gate:memory.write:nope:deadbeef", now=1000)

    def test_external_mutation_invalidates_receipt(self):
        mem = GovernedMemory()
        receipt = mem.write("k", {"v": 1}, issued_at=1000)
        # Simulate external mutation bypassing write().
        mem._store["k"] = ({"v": 2}, receipt.receipt_id)
        with self.assertRaises(GovernedMemoryError):
            mem.read("k", receipt.receipt_id, now=1001)

    def test_revoke_removes_entry(self):
        mem = GovernedMemory()
        receipt = mem.write("k", "v", issued_at=1000)
        mem.revoke("k", reason="stale plan", now=1001)
        with self.assertRaises(GovernedMemoryError):
            mem.read("k", receipt.receipt_id, now=1002)
        with self.assertRaises(ValueError):
            mem.revoke("k", reason="", now=1003)

    def test_history_is_append_only(self):
        mem = GovernedMemory()
        mem.write("k", "v1", issued_at=1000)
        mem.write("k", "v2", issued_at=1001)
        mem.write("other", "x", issued_at=1002)
        self.assertEqual(len(mem.history()), 3)
        self.assertEqual(len(mem.history("k")), 2)
        seqs = [h["seq"] for h in mem.history()]
        self.assertEqual(seqs, [1, 2, 3])

    def test_digest_matches_tool_receipt_canonicalization(self):
        # Same canonical JSON => same digest as tool_receipt's function.
        from tool_receipt import canonical_sha256_hex as tool_digest

        value = {"b": [1, 2], "a": "x"}
        self.assertEqual(canonical_sha256_hex(value), tool_digest(value))

    def test_receipt_for_returns_current(self):
        mem = GovernedMemory()
        self.assertIsNone(mem.receipt_for("k"))
        receipt = mem.write("k", "v", issued_at=1000)
        self.assertEqual(mem.receipt_for("k").receipt_id, receipt.receipt_id)


if __name__ == "__main__":
    unittest.main()
