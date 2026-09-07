import tempfile
import unittest
from pathlib import Path
from route_replay import MigrationError, MigrationRegistry, lineage_for_retry, recover_cursor

class MigrationTests(unittest.TestCase):
    def test_registered_lossless_migration_and_chain(self):
        registry = MigrationRegistry()
        registry.register("northstar.route-journal.v0", "northstar.route-journal.v1",
                          lambda value: {**value, "schema_version": "northstar.route-journal.v1"})
        value, chain = registry.migrate({"schema_version":"northstar.route-journal.v0", "idempotency_key":"x"},
                                        target_version="northstar.route-journal.v1")
        self.assertEqual(value["schema_version"], "northstar.route-journal.v1")
        self.assertEqual(chain, ("northstar.route-journal.v0->northstar.route-journal.v1",))

    def test_unknown_migration_fails_closed(self):
        with self.assertRaises(MigrationError):
            MigrationRegistry().migrate({"schema_version":"unknown"}, target_version="northstar.route-journal.v1")

    def test_transform_cannot_drop_identity(self):
        registry = MigrationRegistry()
        registry.register("v0", "v1", lambda value: {"schema_version":"v1"})
        with self.assertRaises(MigrationError):
            registry.migrate({"schema_version":"v0", "idempotency_key":"x"}, target_version="v1")

class RecoveryTests(unittest.TestCase):
    def test_cursor_skips_truncated_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "route.jsonl"
            path.write_text('{"idempotency_key":"a"}\n{"broken":', encoding="utf-8")
            cursor = recover_cursor(path)
            self.assertEqual(cursor.sequence, 1)
            self.assertEqual(cursor.last_idempotency_key, "a")

    def test_complete_corrupt_line_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "route.jsonl"
            path.write_text('{broken}\n', encoding="utf-8")
            with self.assertRaises(MigrationError): recover_cursor(path)

    def test_retry_lineage_preserves_parent(self):
        lineage = lineage_for_retry({"idempotency_key":"route-1", "attempt":1}, retry_idempotency_key="route-2", receipt_id="receipt-2")
        self.assertEqual((lineage.parent_id, lineage.attempt, lineage.cause), ("route-1", 2, "retry"))

if __name__ == '__main__': unittest.main()
