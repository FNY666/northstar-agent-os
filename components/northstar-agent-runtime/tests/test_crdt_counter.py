"""Targeted tests for the CRDT counter interface."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

from crdt_counter import (
    AUDIT_SCHEMA,
    CRDT_COUNTER_SCHEMA,
    CRDT_COUNTER_VERSION,
    KIND_COUNTER_REGISTERED,
    KIND_DECREMENTED,
    KIND_INCREMENTED,
    KIND_MERGED,
    KIND_REJECTED,
    BadCounterError,
    BadStateError,
    CRDTCounter,
    CRDTCounterError,
    CounterRecord,
    DecrementRecord,
    DuplicateCounterError,
    IncrementRecord,
    MergeRecord,
    SeqOrderError,
    UnknownCounterError,
    ValueReport,
    crdt_counter_audit_event,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "crdt_counter.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(CRDT_COUNTER_VERSION, "crdt-counter.v1")
        self.assertEqual(CRDT_COUNTER_SCHEMA, "northstar.crdt-counter.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "threading", "dataclasses", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.mgr = CRDTCounter()

    def test_register_roundtrip(self):
        rec = self.mgr.register("votes", seq=1)
        self.assertIsInstance(rec, CounterRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.counter_id, "votes")
        self.assertEqual(rec.pos, ())
        self.assertEqual(rec.neg, ())
        self.assertEqual(rec.value(), 0)
        self.assertEqual(self.mgr.counter_ids(), ("votes",))

    def test_register_duplicate_refused(self):
        self.mgr.register("votes", seq=1)
        with self.assertRaises(DuplicateCounterError):
            self.mgr.register("votes", seq=2)
        self.assertEqual(self.mgr.counter_ids(), ("votes",))

    def test_register_bad_id(self):
        for i, bad in enumerate(("", "   ", None, 42), start=2):
            with self.assertRaises(BadCounterError):
                self.mgr.register(bad, seq=i)
        self.mgr.register("ok", seq=99)  # fresh seq works


class TestIncrement(unittest.TestCase):
    def setUp(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)

    def test_increment_happy_path(self):
        rec = self.mgr.increment("c", "r1", seq=2, amount=3)
        self.assertIsInstance(rec, IncrementRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.entry, 3)
        self.assertEqual(rec.value, 3)
        self.assertEqual(self.mgr.value("c", seq=0).value, 3)

    def test_increment_accumulates_per_replica(self):
        self.mgr.increment("c", "r1", seq=2, amount=2)
        rec = self.mgr.increment("c", "r1", seq=3, amount=4)
        self.assertEqual(rec.entry, 6)
        self.assertEqual(self.mgr.value("c", seq=0).value, 6)
        # another replica is tracked separately
        self.mgr.increment("c", "r2", seq=4, amount=1)
        self.assertEqual(self.mgr.value("c", seq=0).value, 7)

    def test_increment_bad_inputs(self):
        for i, bad in enumerate((0, -1, True, 1.5, "3"), start=2):
            with self.assertRaises(BadCounterError):
                self.mgr.increment("c", "r1", seq=i, amount=bad)
        with self.assertRaises(UnknownCounterError):
            self.mgr.increment("nope", "r1", seq=98)
        with self.assertRaises(BadCounterError):
            self.mgr.increment("c", "", seq=99)


class TestDecrement(unittest.TestCase):
    def setUp(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)
        self.mgr.increment("c", "r1", seq=2, amount=5)

    def test_decrement_happy_path(self):
        rec = self.mgr.decrement("c", "r1", seq=3, amount=2)
        self.assertIsInstance(rec, DecrementRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.entry, 2)
        self.assertEqual(rec.value, 3)

    def test_decrement_below_zero_is_data(self):
        # PN-counters never borrow: the value may go negative as data.
        rec = self.mgr.decrement("c", "r2", seq=3, amount=10)
        self.assertEqual(rec.value, -5)
        self.assertEqual(self.mgr.value("c", seq=0).value, -5)

    def test_decrement_bad_inputs(self):
        for i, bad in enumerate((0, -2, False, 2.0, "1"), start=4):
            with self.assertRaises(BadCounterError):
                self.mgr.decrement("c", "r1", seq=i, amount=bad)
        with self.assertRaises(UnknownCounterError):
            self.mgr.decrement("nope", "r1", seq=98)


class TestMerge(unittest.TestCase):
    def _divergent(self):
        a, b = CRDTCounter(), CRDTCounter()
        a.register("x", seq=1)
        b.register("x", seq=1)
        a.increment("x", "ra", seq=2, amount=5)
        b.increment("x", "rb", seq=2, amount=7)
        b.decrement("x", "rb", seq=3, amount=2)
        return a, b

    def test_merge_converges(self):
        a, b = self._divergent()
        pos_b, neg_b = b.state("x")
        rec = a.merge("x", {"pos": dict(pos_b), "neg": dict(neg_b)}, seq=4)
        self.assertIsInstance(rec, MergeRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.merged_replicas, 2)
        self.assertEqual(rec.value, 10)
        self.assertTrue(rec.remote_digest.startswith("sha256:"))
        self.assertEqual(a.value("x", seq=0).value, 10)

    def test_merge_commutes(self):
        a, b = self._divergent()
        sa = {"pos": dict(a.state("x")[0]), "neg": dict(a.state("x")[1])}
        sb = {"pos": dict(b.state("x")[0]), "neg": dict(b.state("x")[1])}
        ra = a.merge("x", sb, seq=4)
        rb = b.merge("x", sa, seq=4)
        self.assertEqual(ra.value, rb.value)
        self.assertEqual(
            a.value("x", seq=0).digest is not None, True
        )

    def test_merge_idempotent(self):
        a, b = self._divergent()
        pos_b, neg_b = b.state("x")
        remote = {"pos": dict(pos_b), "neg": dict(neg_b)}
        r1 = a.merge("x", remote, seq=4)
        r2 = a.merge("x", remote, seq=5)
        self.assertEqual(r1.value, r2.value)
        self.assertEqual(r1.merged_replicas, r2.merged_replicas)

    def test_merge_empty_remote_is_noop(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)
        self.mgr.increment("c", "r1", seq=2, amount=4)
        rec = self.mgr.merge("c", {"pos": {}, "neg": {}}, seq=3)
        self.assertEqual(rec.value, 4)
        self.assertEqual(rec.merged_replicas, 1)

    def test_merge_bad_state(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)
        bad_states = [
            None,
            "x",
            {"pos": {}},
            {"pos": {}, "neg": {}, "extra": 1},
            {"pos": {"r1": -1}, "neg": {}},
            {"pos": {"r1": True}, "neg": {}},
            {"pos": {"r1": 1.5}, "neg": {}},
            {"pos": {"": 1}, "neg": {}},
            {"pos": [], "neg": {}},
            {"pos": {"r1": 1}, "neg": "nope"},
        ]
        for i, bad in enumerate(bad_states, start=2):
            with self.assertRaises(BadStateError):
                self.mgr.merge("c", bad, seq=i)

    def test_merge_unknown_counter(self):
        mgr = CRDTCounter()
        with self.assertRaises(UnknownCounterError):
            mgr.merge("nope", {"pos": {}, "neg": {}}, seq=1)


class TestReadViews(unittest.TestCase):
    def setUp(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)
        self.mgr.increment("c", "r1", seq=2, amount=3)

    def test_value_is_pure_read(self):
        rep = self.mgr.value("c", seq=3)
        self.assertIsInstance(rep, ValueReport)
        self.assertTrue(rep.verify())
        self.assertEqual(rep.value, 3)
        # seq not consumed: a mutation may reuse it
        self.mgr.increment("c", "r1", seq=3, amount=1)
        self.assertEqual(self.mgr.value("c", seq=0).value, 4)

    def test_value_unknown_counter(self):
        with self.assertRaises(UnknownCounterError):
            self.mgr.value("nope", seq=1)

    def test_state_snapshot(self):
        pos, neg = self.mgr.state("c")
        self.assertEqual(pos, (("r1", 3),))
        self.assertEqual(neg, ())
        with self.assertRaises(UnknownCounterError):
            self.mgr.state("nope")


class TestSeqDiscipline(unittest.TestCase):
    def setUp(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)

    def test_seq_rewind_refused(self):
        self.mgr.increment("c", "r1", seq=2)
        with self.assertRaises(SeqOrderError):
            self.mgr.increment("c", "r1", seq=2)
        with self.assertRaises(SeqOrderError):
            self.mgr.merge("c", {"pos": {}, "neg": {}}, seq=1)

    def test_failed_mutation_consumes_seq(self):
        with self.assertRaises(BadStateError):
            self.mgr.merge("c", {"pos": {}}, seq=2)
        # seq 2 is now burned even though the merge failed
        with self.assertRaises(SeqOrderError):
            self.mgr.increment("c", "r1", seq=2)
        self.mgr.increment("c", "r1", seq=3)
        self.assertEqual(self.mgr.value("c", seq=0).value, 1)

    def test_bool_seq_refused(self):
        with self.assertRaises(CRDTCounterError):
            self.mgr.increment("c", "r1", seq=True)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.mgr = CRDTCounter()
        self.mgr.register("c", seq=1)
        self.mgr.increment("c", "r1", seq=2, amount=2)
        self.mgr.decrement("c", "r2", seq=3, amount=1)
        pos, neg = self.mgr.state("c")
        self.mgr.merge("c", {"pos": dict(pos), "neg": dict(neg)}, seq=4)
        with self.assertRaises(DuplicateCounterError):
            self.mgr.register("c", seq=5)

    def test_audit_kinds(self):
        kinds = [row["kind"] for row in self.mgr.audit_log()]
        self.assertEqual(
            kinds,
            [
                KIND_COUNTER_REGISTERED,
                KIND_INCREMENTED,
                KIND_DECREMENTED,
                KIND_MERGED,
                KIND_REJECTED,
            ],
        )

    def test_audit_shapes(self):
        for row in self.mgr.audit_log():
            self.assertEqual(row["schema"], "audit.ndjson/1")
            self.assertEqual(row["module"], "crdt_counter")
            self.assertEqual(row["module_version"], "crdt-counter.v1")
            self.assertIn("detail", row)
        inc = self.mgr.audit_log()[1]["detail"]
        self.assertEqual(inc["counter_id"], "c")
        self.assertEqual(inc["replica_id"], "r1")
        self.assertEqual(inc["amount"], 2)
        self.assertEqual(inc["value"], 2)
        self.assertTrue(inc["digest"].startswith("sha256:"))

    def test_audit_bad_kind(self):
        with self.assertRaises(CRDTCounterError):
            crdt_counter_audit_event("bogus", seq=1)


class TestMain(unittest.TestCase):
    def test_main(self):
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("crdt-counter OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
