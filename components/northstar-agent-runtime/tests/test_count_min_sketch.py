"""Targeted tests for count_min_sketch.py."""

import unittest

from count_min_sketch import (
    COUNT_MIN_SKETCH_VERSION,
    SCHEMA_PIN,
    CountMinSketch,
    SketchSummary,
    countmin_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(COUNT_MIN_SKETCH_VERSION, "count-min-sketch.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.count-min-sketch.v1")


class TestConstructor(unittest.TestCase):
    def test_zero_width_rejected(self):
        with self.assertRaises(ValueError):
            CountMinSketch(0, 3)

    def test_zero_depth_rejected(self):
        with self.assertRaises(ValueError):
            CountMinSketch(10, 0)

    def test_bool_rejected(self):
        with self.assertRaises(TypeError):
            CountMinSketch(True, 3)
        with self.assertRaises(TypeError):
            CountMinSketch(10, False)

    def test_empty_salt_rejected(self):
        with self.assertRaises(ValueError):
            CountMinSketch(10, 3, salt=b"")

    def test_properties(self):
        s = CountMinSketch(100, 5)
        self.assertEqual(s.width, 100)
        self.assertEqual(s.depth, 5)
        self.assertEqual(s.total_adds, 0)


class TestAddEstimate(unittest.TestCase):
    def test_estimate_unseen_is_zero(self):
        s = CountMinSketch(100, 5)
        self.assertEqual(s.estimate("never-added"), 0)

    def test_add_then_estimate_exact(self):
        s = CountMinSketch(100, 5)
        s.add("a")
        s.add("a")
        s.add("b")
        self.assertEqual(s.estimate("a"), 2)
        self.assertEqual(s.estimate("b"), 1)

    def test_add_with_count(self):
        s = CountMinSketch(100, 5)
        s.add("a", count=7)
        self.assertEqual(s.estimate("a"), 7)
        self.assertEqual(s.total_adds, 7)

    def test_never_undercounts(self):
        s = CountMinSketch(64, 4)
        truth = {"x": 0, "y": 0, "z": 0}
        items = ["x", "y", "x", "z", "x", "y"]
        for it in items:
            s.add(it)
            truth[it] += 1
        for it, true_count in truth.items():
            self.assertGreaterEqual(s.estimate(it), true_count)

    def test_bytes_item(self):
        s = CountMinSketch(100, 5)
        s.add(b"raw-bytes")
        self.assertEqual(s.estimate(b"raw-bytes"), 1)

    def test_bool_count_rejected(self):
        s = CountMinSketch(100, 5)
        with self.assertRaises(TypeError):
            s.add("a", count=True)

    def test_zero_count_rejected(self):
        s = CountMinSketch(100, 5)
        with self.assertRaises(ValueError):
            s.add("a", count=0)

    def test_bad_item_types_rejected(self):
        s = CountMinSketch(100, 5)
        for bad in (True, 123, None, ["a"], object()):
            with self.assertRaises(TypeError):
                s.add(bad)
            with self.assertRaises(TypeError):
                s.estimate(bad)

    def test_deterministic(self):
        s1 = CountMinSketch(64, 4)
        s2 = CountMinSketch(64, 4)
        for it in ["a", "b", "c", "a", "a"]:
            s1.add(it)
            s2.add(it)
        self.assertEqual(s1.estimate("a"), s2.estimate("a"))


class TestGuarantee(unittest.TestCase):
    def test_with_guarantee_sizing(self):
        s = CountMinSketch.with_guarantee(epsilon=0.01, delta=0.01)
        self.assertTrue(s.width >= 272)   # ceil(e / 0.01)
        self.assertTrue(s.depth >= 5)     # ceil(ln(100))

    def test_bad_epsilon_delta_rejected(self):
        with self.assertRaises(ValueError):
            CountMinSketch.with_guarantee(epsilon=0.0, delta=0.01)
        with self.assertRaises(ValueError):
            CountMinSketch.with_guarantee(epsilon=1.5, delta=0.01)
        with self.assertRaises(ValueError):
            CountMinSketch.with_guarantee(epsilon=0.01, delta=0.0)
        with self.assertRaises(TypeError):
            CountMinSketch.with_guarantee(epsilon=True, delta=0.01)

    def test_error_bound_method(self):
        s = CountMinSketch.with_guarantee(epsilon=0.01, delta=0.01)
        self.assertTrue(s.error_bound(epsilon=0.01, delta=0.01))
        self.assertFalse(s.error_bound(epsilon=0.0001, delta=0.0001))

    def test_overestimate_within_bound(self):
        import math
        epsilon, delta = 0.1, 0.05
        s = CountMinSketch.with_guarantee(epsilon=epsilon, delta=delta)
        for i in range(1000):
            s.add(f"key-{i}")
        bound = epsilon * s.total_adds
        # estimate(key-0) must not exceed true count (1) + bound
        self.assertLessEqual(s.estimate("key-0"), 1 + bound)


class TestMerge(unittest.TestCase):
    def test_merge_unions_counts(self):
        s1 = CountMinSketch(64, 4)
        s2 = CountMinSketch(64, 4)
        s1.add("a", count=3)
        s2.add("a", count=4)
        s2.add("b", count=2)
        s1.merge(s2)
        self.assertEqual(s1.estimate("a"), 7)
        self.assertEqual(s1.estimate("b"), 2)
        self.assertEqual(s1.total_adds, 9)

    def test_merge_shape_mismatch_rejected(self):
        s1 = CountMinSketch(64, 4)
        s2 = CountMinSketch(32, 4)
        with self.assertRaises(ValueError):
            s1.merge(s2)

    def test_merge_salt_mismatch_rejected(self):
        s1 = CountMinSketch(64, 4, salt=b"salt-a")
        s2 = CountMinSketch(64, 4, salt=b"salt-b")
        with self.assertRaises(ValueError):
            s1.merge(s2)

    def test_merge_non_sketch_rejected(self):
        s = CountMinSketch(64, 4)
        with self.assertRaises(TypeError):
            s.merge({"width": 64})


class TestSummary(unittest.TestCase):
    def test_summary_record(self):
        s = CountMinSketch(64, 4)
        s.add("a", count=2)
        rec = s.summary()
        self.assertIsInstance(rec, SketchSummary)
        self.assertEqual(rec.width, 64)
        self.assertEqual(rec.total_adds, 2)
        self.assertEqual(rec.schema, SCHEMA_PIN)
        d = rec.as_dict()
        self.assertEqual(d["depth"], 4)

    def test_summary_frozen(self):
        s = CountMinSketch(64, 4)
        rec = s.summary()
        with self.assertRaises(Exception):
            rec.total_adds = 99  # frozen dataclass


class TestAuditEvent(unittest.TestCase):
    def _digest(self):
        return "sha256:" + "ab" * 32

    def test_add_event(self):
        ev = countmin_audit_event("add", self._digest(), estimate=3, seq=1)
        self.assertEqual(ev["kind"], "count-min-sketch")
        self.assertEqual(ev["action"], "add")
        self.assertEqual(ev["estimate"], 3)
        self.assertEqual(ev["audit_seq"], 1)
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_estimate_and_merge_events(self):
        ev = countmin_audit_event("estimate", self._digest(), estimate=0, seq=2)
        self.assertEqual(ev["action"], "estimate")
        ev2 = countmin_audit_event("merge", self._digest(), estimate=5, seq=3)
        self.assertEqual(ev2["action"], "merge")

    def test_bad_action_rejected(self):
        with self.assertRaises(ValueError):
            countmin_audit_event("drop", self._digest(), estimate=0, seq=0)

    def test_bad_hash_rejected(self):
        with self.assertRaises(ValueError):
            countmin_audit_event("add", "not-a-digest", estimate=0, seq=0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            countmin_audit_event("add", self._digest(), estimate=0, seq=-1)
        with self.assertRaises(TypeError):
            countmin_audit_event("add", self._digest(), estimate=0, seq=True)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        from count_min_sketch import main
        main()


if __name__ == "__main__":
    unittest.main()
