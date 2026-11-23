"""Tests for migration_runner: 15 cases."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

import migration_runner as mr
from migration_runner import MigrationRunner


def _sql(n):
    return f"ALTER TABLE t ADD c{n} INT;", f"ALTER TABLE t DROP COLUMN c{n};"


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(mr.MIGRATION_RUNNER_VERSION, "migration-runner.v1")
        self.assertEqual(mr.MIGRATION_RUNNER_SCHEMA,
                         "northstar.migration-runner.v1")
        self.assertEqual(mr.AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        src = open(mr.__file__).read()
        tree = ast.parse(src)
        allowed = {"__future__", "re", "threading", "dataclasses", "typing",
                   "hashlib", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip(self):
        r = MigrationRunner()
        up, down = _sql(1)
        rec = r.register("1.0", "first", 1, up_sql=up, down_sql=down)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.version, "1.0")
        self.assertEqual(r.migration(rec.id).version, "1.0")
        self.assertEqual(rec.record_digest, mr._pin(
            "migration", rec.id, "1.0", "first",
            mr._pin("sql", up), mr._pin("sql", down)))

    def test_register_duplicate_version(self):
        r = MigrationRunner()
        r.register("1", "a", 1)
        with self.assertRaises(mr.DuplicateMigrationError):
            r.register("1", "b", 2)
        # failed mutation consumed its seq: next op must use a higher seq
        with self.assertRaises(mr.SeqOrderError):
            r.register("2", "c", 2)

    def test_register_bad_inputs(self):
        r = MigrationRunner()
        seq = 1
        for bad in ("", None, 1, True):
            with self.assertRaises(mr.BadMigrationError):
                r.register(bad, "x", seq)
            seq += 1
            with self.assertRaises(mr.BadMigrationError):
                r.register("v" + str(bad), bad, seq)
            seq += 1
        with self.assertRaises(mr.BadMigrationError):
            r.register("1", "x", seq, up_sql=123)
        seq += 1
        with self.assertRaises(mr.BadMigrationError):
            r.register("1", "x", seq, down_sql=123)

    def test_seq_ordering(self):
        r = MigrationRunner()
        r.register("1", "a", 1)
        with self.assertRaises(mr.SeqOrderError):
            r.register("2", "b", 1)     # rewind
        with self.assertRaises(mr.MigrationRunnerError):
            r.register("2", "b", True)  # bool seq refused
        with self.assertRaises(mr.MigrationRunnerError):
            r.register("2", "b", -1)    # negative seq refused
        with self.assertRaises(mr.MigrationRunnerError):
            r.register("2", "b", 1.5)   # non-int refused
        rec = r.register("2", "b", 2)
        self.assertEqual(rec.version, "2")

    def test_unknown_migration_lookup(self):
        r = MigrationRunner()
        with self.assertRaises(mr.UnknownMigrationError):
            r.migration("mig-999")


class TestUpDownStatus(unittest.TestCase):
    def _reg3(self):
        r = MigrationRunner()
        up, down = _sql(0)
        ids = [r.register(v, n, i + 1, up_sql=up, down_sql=down).id
               for i, (v, n) in enumerate(
                   [("1.2", "a"), ("1.10", "b"), ("2", "c")])]
        return r, ids

    def test_up_version_order(self):
        r, ids = self._reg3()
        rep = r.up(4)
        self.assertEqual(rep.applied_ids, tuple(ids))
        self.assertTrue(rep.verify())
        st = r.status(5)
        self.assertTrue(st.verify())
        self.assertEqual(st.current_version, "2")
        self.assertEqual(st.applied_ids, tuple(ids))
        self.assertEqual(st.pending_ids, ())

    def test_up_idempotent_and_target(self):
        r, ids = self._reg3()
        rep = r.up(4, target="1.2")
        self.assertEqual(rep.applied_ids, (ids[0],))
        self.assertEqual(rep.target, "1.2")
        st = r.status(5)
        self.assertEqual(st.current_version, "1.2")
        self.assertEqual(st.pending_ids, tuple(ids[1:]))
        again = r.up(6, target="1.2")
        self.assertEqual(again.applied_ids, ())  # nothing pending under target

    def test_up_unknown_target(self):
        r, _ = self._reg3()
        with self.assertRaises(mr.UnknownTargetError):
            r.up(4, target="9.9")

    def test_down_reverse_order(self):
        r, ids = self._reg3()
        r.up(4)
        rep = r.down(5, target="1.2")
        self.assertEqual(rep.reverted_ids, tuple(reversed(ids[1:])))
        self.assertTrue(rep.verify())
        st = r.status(6)
        self.assertEqual(st.current_version, "1.2")
        self.assertEqual(st.applied_ids, (ids[0],))

    def test_down_missing_down_refused(self):
        r = MigrationRunner()
        r.register("1", "no-down", 1, up_sql="SELECT 1;")
        r.up(2)
        with self.assertRaises(mr.MissingDownError):
            r.down(3)
        # ledger unchanged: the migration is still applied
        st = r.status(4)
        self.assertEqual(st.current_version, "1")

    def test_down_empty_ledger(self):
        r, _ = self._reg3()
        rep = r.down(4)
        self.assertEqual(rep.reverted_ids, ())

    def test_status_is_read(self):
        r, ids = self._reg3()
        st = r.status(9)
        self.assertTrue(st.verify())
        # a read does not consume seq: the same seq validates again
        st2 = r.status(9)
        self.assertEqual(st2.current_version, None)
        # next mutation can still use a seq just above 9 (nothing consumed)
        r.up(10)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_sql_leak_ban(self):
        r = MigrationRunner()
        up, down = _sql(1)
        r.register("1", "a", 1, up_sql=up, down_sql=down)
        r.up(2)
        r.down(3)
        log = r.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertEqual(kinds, ["migration-registered", "migrated-up",
                                "migrated-down"])
        blob = str(log)
        self.assertNotIn(up, blob)
        self.assertNotIn(down, blob)
        for e in log:
            self.assertEqual(e["schema"], mr.AUDIT_SCHEMA)
            self.assertEqual(e["module"], mr.MIGRATION_RUNNER_VERSION)

    def test_audit_bad_kind_and_banned_field(self):
        with self.assertRaises(mr.MigrationRunnerError):
            mr.migration_runner_audit_event("nope", 1)
        with self.assertRaises(mr.MigrationRunnerError):
            mr.migration_runner_audit_event("migrated-up", 1,
                                            detail={"up_sql": "SELECT 1"})

    def test_main(self):
        mr.main()


if __name__ == "__main__":
    unittest.main()
