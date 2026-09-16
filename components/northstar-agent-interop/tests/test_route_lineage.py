import json
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(COMPONENT_ROOT))

from backend_router import RouteDecision  # noqa: E402
from route_ledger import RouteEvent, RouteReceipt  # noqa: E402
from route_lineage import LineageCursor, LineageEvent, RouteLineage, migrate_v1_to_v2  # noqa: E402


DECISION = RouteDecision.from_dict(
    {
        "schema_version": "northstar.route-decision.v1",
        "route_id": "route-lineage-001",
        "task_id": "task-lineage-001",
        "thread_id": "thread-lineage-001",
        "run_id": "run-lineage-001",
        "actor_id": "actor-lineage-001",
        "workspace_id": "workspace-lineage-001",
        "policy_revision": "policy-lineage-1",
        "step_id": "lineage",
        "trace_id": "trace-lineage-001",
        "input_digest": "sha256:" + "2" * 64,
        "requested_capabilities": ["workspace:read"],
        "deadline_at": 2_900,
        "target_agent_id": "codex",
        "provider": "openai",
        "backend_version": "cli-v1",
        "priority": 10,
        "selected_at": 2_001,
    }
)


class RouteLineageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "lineage.jsonl"

    def tearDown(self):
        self.tempdir.cleanup()

    def decision_event(self):
        return RouteEvent.from_decision(
            DECISION,
            event_type="decision.selected",
            attempt=1,
            idempotency_key="lineage-selected-1",
            recorded_at=2_001,
        )

    def started_event(self, *, sequence=2):
        receipt = RouteReceipt.from_decision(
            DECISION,
            status="started",
            attempt=1,
            latency_ms=12,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="lineage-started-1",
            recorded_at=2_002,
        )
        return RouteEvent.from_receipt(receipt, sequence=sequence)

    def succeeded_event(self, *, sequence=3):
        receipt = RouteReceipt.from_decision(
            DECISION,
            status="succeeded",
            attempt=1,
            latency_ms=42,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="lineage-succeeded-1",
            recorded_at=2_003,
        )
        return RouteEvent.from_receipt(receipt, sequence=sequence)

    def append_three_events(self):
        lineage = RouteLineage(self.path)
        lineage.append(self.decision_event())
        lineage.append(self.started_event(sequence=2))
        lineage.append(self.succeeded_event(sequence=3))
        return lineage.recover().cursor

    def test_append_and_recover_yield_a_verified_v2_digest_chain(self):
        lineage = RouteLineage(self.path)
        first = lineage.append(self.decision_event())
        second = lineage.append(self.started_event(sequence=2))

        recovery = RouteLineage(self.path).recover()

        self.assertEqual(recovery.verdict, "verified")
        self.assertEqual([item.sequence for item in recovery.events], [1, 2])
        self.assertEqual(first.schema_version, "northstar.route-lineage.v2")
        self.assertIsNone(first.prev_event_digest)
        self.assertEqual(second.prev_event_digest, first.event_digest)
        self.assertEqual(recovery.cursor, LineageCursor(2, second.event_digest))
        self.assertEqual(
            recovery.events[0].route_event.to_dict(),
            self.decision_event().to_dict(),
        )

    def test_append_rejects_illegal_route_state_transition(self):
        lineage = RouteLineage(self.path)
        lineage.append(self.decision_event())
        with self.assertRaises(ValueError):
            lineage.append(self.succeeded_event(sequence=2))
        self.assertEqual(len(lineage.recover().events), 1)

    def test_recovery_of_empty_history_is_not_reported_as_verified(self):
        """Nothing was read, so nothing was verified.

        This expectation used to be `verified`, which made a journal that was
        deleted or truncated read exactly like an intact one.
        """
        recovery = RouteLineage(self.path).recover()
        self.assertEqual(recovery.verdict, "empty")
        self.assertEqual(recovery.events, ())
        self.assertIsNone(recovery.cursor)

    def test_deleting_the_journal_stops_it_reading_as_verified(self):
        lineage = RouteLineage(self.path)
        lineage.append(self.decision_event())
        self.assertEqual(len(RouteLineage(self.path).recover().events), 1)
        self.path.unlink()
        recovery = RouteLineage(self.path).recover()
        self.assertEqual(recovery.verdict, "empty")
        self.assertEqual(recovery.events, ())
        self.assertNotEqual(RouteLineage(self.path).replay_verdict().verdict, "replayable")

    def test_truncating_the_journal_stops_it_reading_as_verified(self):
        lineage = RouteLineage(self.path)
        lineage.append(self.decision_event())
        self.path.write_text("", encoding="utf-8")
        recovery = RouteLineage(self.path).recover()
        self.assertEqual(recovery.verdict, "empty")
        self.assertEqual(recovery.events, ())

    def test_an_intact_journal_still_verifies(self):
        lineage = RouteLineage(self.path)
        lineage.append(self.decision_event())
        recovery = RouteLineage(self.path).recover()
        self.assertEqual(recovery.verdict, "verified")
        self.assertEqual(len(recovery.events), 1)

    def test_recovery_rejects_structurally_valid_but_illegal_route_history(self):
        first = self.decision_event()
        second = RouteEvent.from_receipt(
            RouteReceipt.from_decision(
                DECISION,
                status="succeeded",
                attempt=1,
                latency_ms=42,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="lineage-succeeded-1",
                recorded_at=2_003,
            ),
            sequence=2,
        )
        first_lineage = LineageEvent.create(first, sequence=1, prev_event_digest=None)
        second_lineage = LineageEvent.create(second, sequence=2, prev_event_digest=first_lineage.event_digest)
        self.path.write_text(
            "\n".join(
                json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True)
                for event in (first_lineage, second_lineage)
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            RouteLineage(self.path).recover()

    def test_recovery_rejects_mutated_middle_envelope(self):
        cursor = self.append_three_events()
        rows = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]
        rows[1]["route_event"]["recorded_at"] += 1
        self.path.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            RouteLineage(self.path).recover(expected_cursor=cursor)

    def test_recovery_rejects_reordered_or_middle_deleted_envelope(self):
        cursor = self.append_three_events()
        rows = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join((rows[0], rows[2])) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            RouteLineage(self.path).recover(expected_cursor=cursor)

    def test_recovery_rejects_suffix_rollback_when_caller_pins_cursor(self):
        cursor = self.append_three_events()
        rows = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(rows[:-1]) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            RouteLineage(self.path).recover(expected_cursor=cursor)


class RouteLineageMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.source = self.root / "v1-events.jsonl"
        self.target = self.root / "v2-lineage.jsonl"

    def tearDown(self):
        self.tempdir.cleanup()

    def make_v1_history(self):
        route_ledger = __import__("route_ledger")
        ledger = route_ledger.RouteLedger(self.source)
        ledger.append_decision(
            DECISION,
            attempt=1,
            idempotency_key="lineage-selected-1",
            recorded_at=2_001,
        )
        ledger.append_receipt(
            RouteReceipt.from_decision(
                DECISION,
                status="started",
                attempt=1,
                latency_ms=12,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="lineage-started-1",
                recorded_at=2_002,
            )
        )
        return self.source

    def succeeded_event(self):
        receipt = RouteReceipt.from_decision(
            DECISION,
            status="succeeded",
            attempt=1,
            latency_ms=42,
            failure_class=None,
            error_code=None,
            retryable=False,
            idempotency_key="lineage-succeeded-1",
            recorded_at=2_003,
        )
        return RouteEvent.from_receipt(receipt, sequence=3)

    def test_migration_preserves_source_creates_distinct_verified_target_and_allows_append(self):
        source = self.make_v1_history()
        source_bytes = source.read_bytes()

        result = migrate_v1_to_v2(source, self.target)
        self.assertEqual(source.read_bytes(), source_bytes)
        self.assertEqual(result.verdict, "verified")
        lineage = RouteLineage(self.target)
        appended = lineage.append(self.succeeded_event())
        self.assertEqual(lineage.recover().cursor, LineageCursor(3, appended.event_digest))

    def test_migration_rejects_invalid_source_without_creating_target(self):
        self.source.write_text('{"not":"route event"}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            migrate_v1_to_v2(self.source, self.target)
        self.assertFalse(self.target.exists())

    def test_migration_rejects_structurally_valid_but_illegal_route_history(self):
        decision = RouteEvent.from_decision(
            DECISION,
            event_type="decision.selected",
            attempt=1,
            idempotency_key="lineage-selected-1",
            recorded_at=2_001,
        )
        succeeded = RouteEvent.from_receipt(
            RouteReceipt.from_decision(
                DECISION,
                status="succeeded",
                attempt=1,
                latency_ms=42,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="lineage-succeeded-1",
                recorded_at=2_003,
            ),
            sequence=2,
        )
        self.source.write_text(
            "\n".join(
                json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True)
                for event in (decision, succeeded)
            )
            + "\n",
            encoding="utf-8",
        )
        source_bytes = self.source.read_bytes()
        with self.assertRaises(ValueError):
            migrate_v1_to_v2(self.source, self.target)
        self.assertEqual(self.source.read_bytes(), source_bytes)
        self.assertFalse(self.target.exists())

    def test_migration_rejects_same_or_preexisting_target_without_overwrite(self):
        source = self.make_v1_history()
        with self.assertRaises(ValueError):
            migrate_v1_to_v2(source, source)
        self.target.write_text("do-not-overwrite\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            migrate_v1_to_v2(source, self.target)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "do-not-overwrite\n")


if __name__ == "__main__":
    unittest.main()
