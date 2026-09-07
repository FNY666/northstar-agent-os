"""The durable-run bridge into the canonical audit NDJSON feed."""
import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from durable_audit import COMPONENT, event_to_audit, events_to_ndjson  # noqa: E402


def sample_event(**overrides):
    event = {
        "schema_version": "durable.event.v1",
        "event_id": "event-001",
        "task_id": "task-001",
        "thread_id": "thread-001",
        "run_id": "run-001",
        "step_id": "step-002",
        "sequence": 2,
        "event_type": "step.completed",
        "status": "completed",
        "occurred_at": 1_001,
        "idempotency_key": "run-001:step-002",
        "trace_id": "trace-abc",
        "payload_digest": "sha256:abc",
    }
    event.update(overrides)
    return event


class EventToAuditTests(unittest.TestCase):
    def test_event_maps_into_a_valid_audit_record(self):
        record = event_to_audit(sample_event())
        self.assertEqual(record["schema_version"], "audit.ndjson/1")
        self.assertEqual(record["component"], COMPONENT)
        self.assertEqual(record["event"], "step.completed")
        self.assertEqual(record["seq"], 2)
        self.assertEqual(record["ts"], "1970-01-01T00:16:41.000Z")
        self.assertEqual(record["level"], "info")
        self.assertEqual(record["run_id"], "run-001")
        self.assertEqual(
            record["payload"],
            {
                "event_id": "event-001",
                "task_id": "task-001",
                "thread_id": "thread-001",
                "run_id": "run-001",
                "step_id": "step-002",
                "event_type": "step.completed",
                "status": "completed",
                "idempotency_key": "run-001:step-002",
                "trace_id": "trace-abc",
                "payload_digest": "sha256:abc",
            },
        )

    def test_failed_status_raises_the_level_to_error(self):
        record = event_to_audit(sample_event(status="failed", event_type="step.failed"))
        self.assertEqual(record["level"], "error")

    def test_denied_and_error_suffixes_are_error_level(self):
        self.assertEqual(event_to_audit(sample_event(status="denied"))["level"], "error")
        self.assertEqual(event_to_audit(sample_event(status="verification_error"))["level"], "error")

    def test_millisecond_occurred_at_is_supported(self):
        record = event_to_audit(sample_event(occurred_at=1_752_000_000_250), occurred_at_is_ms=True)
        self.assertEqual(record["ts"], "2025-07-08T18:40:00.250Z")

    def test_missing_optional_payload_keys_are_skipped(self):
        event = sample_event()
        del event["trace_id"]
        record = event_to_audit(event)
        self.assertNotIn("trace_id", record["payload"])

    def test_events_to_ndjson_is_one_line_per_event(self):
        text = events_to_ndjson([sample_event(sequence=1), sample_event(sequence=2, status="failed")])
        lines = [line for line in text.splitlines() if line]
        self.assertEqual(len(lines), 2)
        self.assertIn('"level":"error"', lines[1])


if __name__ == "__main__":
    unittest.main()
