import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from control_receipt import ControlReceipt, digest_state  # noqa: E402


class ControlReceiptTests(unittest.TestCase):
    def receipt(self, **changes):
        value = {
            "schema_version": "northstar.durable-control-receipt.v1",
            "receipt_id": "ctl-receipt-1",
            "command_id": "command-1",
            "run_id": "run-001",
            "actor_id": "operator-1",
            "operation": "pause",
            "requested_at": 100,
            "outcome": "applied",
            "before_status": "running",
            "after_status": "waiting",
            "before_sequence": 4,
            "after_sequence": 5,
            "event_ids": ["event-005"],
            "event_sequences": [5],
            "state_digest": digest_state({"status": "waiting", "sequence": 5}),
        }
        value.update(changes)
        return value

    def test_receipt_round_trips_canonically(self):
        receipt = ControlReceipt.from_dict(self.receipt())
        self.assertEqual(receipt.to_dict(), self.receipt())
        self.assertEqual(
            ControlReceipt.from_dict(receipt.to_dict()),
            receipt,
        )
        self.assertEqual(
            receipt.canonical_json(),
            ControlReceipt.from_dict(dict(reversed(list(self.receipt().items())))).canonical_json(),
        )
        self.assertTrue(receipt.verify_state({"status": "waiting", "sequence": 5}))
        self.assertFalse(receipt.verify_state({"status": "running", "sequence": 5}))

    def test_noop_receipt_has_no_events_and_invalid_causality_is_rejected(self):
        noop = self.receipt(
            outcome="noop",
            before_status="cancelled",
            after_status="cancelled",
            before_sequence=6,
            after_sequence=6,
            event_ids=[],
            event_sequences=[],
            state_digest=digest_state({"status": "cancelled", "sequence": 6}),
        )
        self.assertEqual(ControlReceipt.from_dict(noop).outcome, "noop")
        with self.assertRaises(ValueError):
            ControlReceipt.from_dict(self.receipt(outcome="applied", event_ids=[], event_sequences=[]))
        with self.assertRaises(ValueError):
            ControlReceipt.from_dict(self.receipt(event_sequences=[4]))


if __name__ == "__main__":
    unittest.main()
