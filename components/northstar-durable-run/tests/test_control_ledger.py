import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from control_ledger import ControlReceiptLedger, command_fingerprint  # noqa: E402
from control_receipt import (  # noqa: E402
    CONTROL_RECEIPT_SCHEMA_VERSION,
    ControlReceipt,
    digest_state,
)


class ControlLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "control-ledger.jsonl"
        self.ledger = ControlReceiptLedger(self.path)
        self.fingerprint = command_fingerprint(
            run_id="run-1",
            actor_id="actor-1",
            workspace_id="workspace-1",
            policy_revision="policy-1",
            operation="pause",
            payload={"reason": "hold"},
        )
        state = {
            "run_id": "run-1",
            "status": "waiting",
            "sequence": 2,
            "steps": {},
        }
        self.receipt = ControlReceipt(
            schema_version=CONTROL_RECEIPT_SCHEMA_VERSION,
            receipt_id="receipt-1",
            command_id="command-1",
            run_id="run-1",
            actor_id="actor-1",
            operation="pause",
            requested_at=100,
            outcome="applied",
            before_status="running",
            after_status="waiting",
            before_sequence=1,
            after_sequence=2,
            event_ids=("event-2",),
            event_sequences=(2,),
            state_digest=digest_state(state),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_fingerprint_is_deterministic_and_claim_bound(self):
        same = command_fingerprint(
            run_id="run-1",
            actor_id="actor-1",
            workspace_id="workspace-1",
            policy_revision="policy-1",
            operation="pause",
            payload={"reason": "hold"},
        )
        changed = command_fingerprint(
            run_id="run-1",
            actor_id="actor-1",
            workspace_id="workspace-1",
            policy_revision="policy-1",
            operation="pause",
            payload={"reason": "other"},
        )
        self.assertEqual(same, self.fingerprint)
        self.assertNotEqual(same, changed)

    def test_record_and_lookup_round_trip_is_durable(self):
        self.assertIsNone(self.ledger.lookup("command-1", self.fingerprint))
        stored = self.ledger.record("command-1", self.fingerprint, self.receipt)
        self.assertEqual(stored, self.receipt)
        reopened = ControlReceiptLedger(self.path)
        self.assertEqual(reopened.lookup("command-1", self.fingerprint), self.receipt)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_same_command_is_idempotent_but_claim_change_is_rejected(self):
        self.ledger.record("command-1", self.fingerprint, self.receipt)
        self.assertEqual(
            self.ledger.record("command-1", self.fingerprint, self.receipt),
            self.receipt,
        )
        changed = command_fingerprint(
            run_id="run-1",
            actor_id="actor-1",
            workspace_id="workspace-1",
            policy_revision="policy-1",
            operation="pause",
            payload={"reason": "other"},
        )
        with self.assertRaises(ValueError):
            self.ledger.lookup("command-1", changed)

    def test_malformed_ledger_fails_closed(self):
        self.path.write_text(json.dumps({"unknown": True}) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.ledger.lookup("command-1", self.fingerprint)

    def test_receipt_command_id_must_match_the_record(self):
        other = ControlReceipt.from_dict(
            {**self.receipt.to_dict(), "command_id": "other-command"}
        )
        with self.assertRaises(ValueError):
            self.ledger.record("command-1", self.fingerprint, other)


if __name__ == "__main__":
    unittest.main()
