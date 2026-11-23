"""Tests for vector_clock."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vector_clock import (  # noqa: E402
    AFTER,
    BEFORE,
    CONCURRENT,
    EQUAL,
    SCHEMA_PIN,
    VECTOR_CLOCK_VERSION,
    VectorClock,
    vector_clock_audit_event,
)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VECTOR_CLOCK_VERSION, "vector-clock.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.vector-clock.v1")


class TestFrozen(unittest.TestCase):
    def test_frozen(self):
        clock = VectorClock(counters={"a": 1})
        with self.assertRaises(Exception):
            clock.counters = {}  # type: ignore[misc]


class TestConstruction(unittest.TestCase):
    def test_empty_clock(self):
        clock = VectorClock(counters={})
        self.assertEqual(clock.counters, {})
        self.assertEqual(clock.get("nobody"), 0)

    def test_counters_copied(self):
        src = {"a": 1}
        clock = VectorClock(counters=src)
        src["a"] = 99
        self.assertEqual(clock.get("a"), 1)

    def test_negative_counter_rejected(self):
        with self.assertRaises(ValueError):
            VectorClock(counters={"a": -1})

    def test_bool_counter_rejected(self):
        with self.assertRaises(TypeError):
            VectorClock(counters={"a": True})

    def test_empty_node_id_rejected(self):
        with self.assertRaises(ValueError):
            VectorClock(counters={"": 1})

    def test_non_str_node_id_rejected(self):
        with self.assertRaises(TypeError):
            VectorClock(counters={123: 1})  # type: ignore[dict-item]

    def test_non_mapping_rejected(self):
        with self.assertRaises(TypeError):
            VectorClock(counters=[("a", 1)])  # type: ignore[arg-type]


class TestTick(unittest.TestCase):
    def test_tick_increments(self):
        clock = VectorClock(counters={"a": 1})
        nxt = clock.tick("a")
        self.assertEqual(nxt.get("a"), 2)

    def test_tick_returns_new_clock(self):
        clock = VectorClock(counters={"a": 1})
        clock.tick("a")
        self.assertEqual(clock.get("a"), 1)

    def test_tick_new_node_starts_at_one(self):
        clock = VectorClock(counters={})
        self.assertEqual(clock.tick("new-node").get("new-node"), 1)

    def test_tick_invalid_id(self):
        clock = VectorClock(counters={})
        with self.assertRaises(ValueError):
            clock.tick("")
        with self.assertRaises(TypeError):
            clock.tick(123)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            clock.tick(True)  # type: ignore[arg-type]


class TestMerge(unittest.TestCase):
    def test_merge_elementwise_max(self):
        a = VectorClock(counters={"x": 2, "y": 1})
        b = VectorClock(counters={"x": 1, "z": 5})
        merged = a.merge(b)
        self.assertEqual(merged.counters, {"x": 2, "y": 1, "z": 5})

    def test_merge_does_not_mutate_inputs(self):
        a = VectorClock(counters={"x": 1})
        b = VectorClock(counters={"x": 2})
        a.merge(b)
        self.assertEqual(a.get("x"), 1)
        self.assertEqual(b.get("x"), 2)

    def test_merge_type_check(self):
        a = VectorClock(counters={})
        with self.assertRaises(TypeError):
            a.merge({"x": 1})  # type: ignore[arg-type]


class TestHappensBefore(unittest.TestCase):
    def test_true_when_all_leq_and_one_strict(self):
        a = VectorClock(counters={"x": 1, "y": 2})
        b = VectorClock(counters={"x": 1, "y": 3})
        self.assertTrue(a.happens_before(b))

    def test_false_when_equal(self):
        a = VectorClock(counters={"x": 1})
        b = VectorClock(counters={"x": 1})
        self.assertFalse(a.happens_before(b))

    def test_false_when_reversed(self):
        a = VectorClock(counters={"x": 2})
        b = VectorClock(counters={"x": 1})
        self.assertFalse(a.happens_before(b))

    def test_false_when_concurrent(self):
        a = VectorClock(counters={"x": 1})
        b = VectorClock(counters={"y": 1})
        self.assertFalse(a.happens_before(b))
        self.assertFalse(b.happens_before(a))

    def test_missing_entry_is_zero(self):
        a = VectorClock(counters={})
        b = VectorClock(counters={"x": 1})
        self.assertTrue(a.happens_before(b))
        self.assertFalse(b.happens_before(a))

    def test_type_check(self):
        a = VectorClock(counters={})
        with self.assertRaises(TypeError):
            a.happens_before("not-a-clock")  # type: ignore[arg-type]


class TestConcurrentAndCompare(unittest.TestCase):
    def test_concurrent_with(self):
        a = VectorClock(counters={"x": 1})
        b = VectorClock(counters={"y": 1})
        self.assertTrue(a.concurrent_with(b))
        self.assertFalse(a.concurrent_with(a))

    def test_compare_before(self):
        a = VectorClock(counters={"x": 1})
        b = VectorClock(counters={"x": 2})
        self.assertEqual(a.compare(b), BEFORE)

    def test_compare_after(self):
        a = VectorClock(counters={"x": 2})
        b = VectorClock(counters={"x": 1})
        self.assertEqual(a.compare(b), AFTER)

    def test_compare_equal(self):
        a = VectorClock(counters={"x": 1, "y": 2})
        b = VectorClock(counters={"y": 2, "x": 1})
        self.assertEqual(a.compare(b), EQUAL)

    def test_compare_concurrent(self):
        a = VectorClock(counters={"x": 1})
        b = VectorClock(counters={"y": 1})
        self.assertEqual(a.compare(b), CONCURRENT)

    def test_compare_type_check(self):
        a = VectorClock(counters={})
        with self.assertRaises(TypeError):
            a.compare(None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            a.concurrent_with(None)  # type: ignore[arg-type]


class TestTickSequenceEndToEnd(unittest.TestCase):
    def test_tick_chain_orders_causally(self):
        base = VectorClock(counters={})
        one = base.tick("a")
        two = one.tick("a")
        self.assertTrue(one.happens_before(two))
        self.assertTrue(base.happens_before(two))
        self.assertEqual(base.compare(two), BEFORE)

    def test_merge_creates_happens_before_edge(self):
        a = VectorClock(counters={}).tick("a")
        b = VectorClock(counters={}).tick("b")
        merged = a.merge(b)
        self.assertTrue(a.happens_before(merged))
        self.assertTrue(b.happens_before(merged))


class TestAsDict(unittest.TestCase):
    def test_as_dict_shape(self):
        d = VectorClock(counters={"b": 2, "a": 1}).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["counters"], {"a": 1, "b": 2})


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        clock = VectorClock(counters={"a": 1})
        ev = vector_clock_audit_event(clock, "tick", 3)
        self.assertEqual(ev["format"], "audit.ndjson/1")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "tick")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["clock"]["counters"], {"a": 1})

    def test_bad_kind_rejected(self):
        clock = VectorClock(counters={})
        with self.assertRaises(ValueError):
            vector_clock_audit_event(clock, "explode", 0)

    def test_bad_seq_rejected(self):
        clock = VectorClock(counters={})
        with self.assertRaises(ValueError):
            vector_clock_audit_event(clock, "merge", -1)
        with self.assertRaises(TypeError):
            vector_clock_audit_event(clock, "merge", True)

    def test_bad_clock_rejected(self):
        with self.assertRaises(TypeError):
            vector_clock_audit_event({}, "tick", 0)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        import vector_clock

        with redirect_stdout(buf):
            vector_clock.main()
        self.assertIn("vector-clock OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
