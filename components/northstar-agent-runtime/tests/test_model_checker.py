"""Tests for model_checker.py (explicit-state model checking)."""

import unittest

from model_checker import (
    MODEL_CHECKER_SCHEMA,
    MODEL_CHECKER_VERSION,
    ExplorationResult,
    LivenessResult,
    ModelChecker,
    ModelCheckerError,
    SafetyResult,
    Trace,
    model_checker_audit_event,
)


def _triangle() -> ModelChecker:
    mc = ModelChecker()
    mc.add_state("a", initial=True)
    mc.add_state("b", labels={"progress"})
    mc.add_state("c")
    mc.add_transition("a", "b", action="go")
    mc.add_transition("b", "c", action="step")
    mc.add_transition("c", "a", action="back")
    return mc


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MODEL_CHECKER_VERSION, "model-checker.v1")

    def test_schema_pin(self):
        self.assertEqual(MODEL_CHECKER_SCHEMA, "northstar.model-checker.v1")


class TestConstruction(unittest.TestCase):
    def test_add_state_happy_path(self):
        mc = ModelChecker()
        self.assertEqual(mc.add_state("s1", initial=True), "s1")
        self.assertEqual(mc.initial, "s1")
        self.assertEqual(mc.labels_of("s1"), frozenset())

    def test_add_state_with_labels(self):
        mc = ModelChecker()
        mc.add_state("s", labels=["p", "q"], initial=True)
        self.assertEqual(mc.labels_of("s"), frozenset({"p", "q"}))

    def test_duplicate_state_rejected(self):
        mc = ModelChecker()
        mc.add_state("s")
        with self.assertRaises(ModelCheckerError):
            mc.add_state("s")

    def test_bad_state_ids(self):
        mc = ModelChecker()
        for bad in ("", 1, None, True, b"s"):
            with self.assertRaises(ModelCheckerError, msg=repr(bad)):
                mc.add_state(bad)

    def test_bad_labels(self):
        mc = ModelChecker()
        with self.assertRaises(ModelCheckerError):
            mc.add_state("s", labels="progress")  # str is not a label list
        with self.assertRaises(ModelCheckerError):
            mc.add_state("s", labels=[""])
        with self.assertRaises(ModelCheckerError):
            mc.add_state("s", labels=[True])

    def test_second_initial_rejected(self):
        mc = ModelChecker()
        mc.add_state("a", initial=True)
        with self.assertRaises(ModelCheckerError):
            mc.add_state("b", initial=True)

    def test_add_transition_happy_path(self):
        mc = ModelChecker()
        mc.add_state("a", initial=True)
        mc.add_state("b")
        mc.add_transition("a", "b", action="go")  # no raise

    def test_transition_unknown_state(self):
        mc = ModelChecker()
        mc.add_state("a", initial=True)
        with self.assertRaises(ModelCheckerError):
            mc.add_transition("a", "ghost")
        with self.assertRaises(ModelCheckerError):
            mc.add_transition("ghost", "a")

    def test_duplicate_transition_idempotent(self):
        mc = ModelChecker()
        mc.add_state("a", initial=True)
        mc.add_state("b")
        mc.add_transition("a", "b")
        mc.add_transition("a", "b")
        self.assertEqual(mc.explore().transitions_explored, 1)

    def test_labels_of_unknown(self):
        mc = ModelChecker()
        with self.assertRaises(ModelCheckerError):
            mc.labels_of("nope")


class TestExplore(unittest.TestCase):
    def test_reachable_set(self):
        result = _triangle().explore()
        self.assertIsInstance(result, ExplorationResult)
        self.assertEqual(result.reachable, frozenset({"a", "b", "c"}))
        self.assertEqual(result.initial, "a")
        self.assertEqual(result.visit_order[0], "a")

    def test_unreachable_excluded(self):
        mc = ModelChecker()
        mc.add_state("a", initial=True)
        mc.add_state("far")
        self.assertEqual(mc.explore().reachable, frozenset({"a"}))

    def test_no_initial_raises(self):
        mc = ModelChecker()
        mc.add_state("a")
        with self.assertRaises(ModelCheckerError):
            mc.explore()

    def test_deterministic_order(self):
        self.assertEqual(
            _triangle().explore().visit_order, _triangle().explore().visit_order
        )


class TestSafety(unittest.TestCase):
    def test_holds_when_clean(self):
        result = _triangle().check_safety({"bad"})
        self.assertIsInstance(result, SafetyResult)
        self.assertTrue(result.holds)
        self.assertIsNone(result.counterexample)

    def test_violation_with_counterexample(self):
        mc = _triangle()
        mc.add_state("boom", labels={"bad"})
        mc.add_transition("b", "boom")
        result = mc.check_safety({"bad"})
        self.assertFalse(result.holds)
        trace = result.counterexample
        self.assertIsNotNone(trace)
        self.assertEqual(trace.states[0], "a")
        self.assertEqual(trace.violated, "boom")
        self.assertEqual(trace.states[-1], "boom")

    def test_counterexample_is_shortest(self):
        mc = ModelChecker()
        mc.add_state("a", initial=True)
        mc.add_state("bad", labels={"bad"})
        mc.add_state("mid")
        mc.add_transition("a", "mid")
        mc.add_transition("mid", "bad")
        mc.add_transition("a", "bad")  # direct edge is shorter
        result = mc.check_safety({"bad"})
        self.assertEqual(result.counterexample.states, ("a", "bad"))

    def test_initial_state_violation(self):
        mc = ModelChecker()
        mc.add_state("a", labels={"bad"}, initial=True)
        result = mc.check_safety({"bad"})
        self.assertFalse(result.holds)
        self.assertEqual(result.counterexample.states, ("a",))

    def test_empty_bad_rejected(self):
        with self.assertRaises(ModelCheckerError):
            _triangle().check_safety(set())

    def test_no_initial_raises(self):
        mc = ModelChecker()
        mc.add_state("a")
        with self.assertRaises(ModelCheckerError):
            mc.check_safety({"bad"})


class TestLiveness(unittest.TestCase):
    def test_holds_on_cycle_with_progress(self):
        result = _triangle().check_liveness({"progress"})
        self.assertIsInstance(result, LivenessResult)
        self.assertTrue(result.holds)
        self.assertIsNone(result.counterexample)

    def test_dead_end_violates(self):
        mc = ModelChecker()
        mc.add_state("a", labels={"progress"}, initial=True)
        mc.add_state("stuck")
        mc.add_transition("a", "stuck")
        result = mc.check_liveness({"progress"})
        self.assertFalse(result.holds)
        self.assertEqual(result.counterexample.violated, "stuck")
        self.assertEqual(result.counterexample.states, ("a", "stuck"))

    def test_sink_cycle_without_progress_violates(self):
        mc = ModelChecker()
        mc.add_state("a", labels={"progress"}, initial=True)
        mc.add_state("x")
        mc.add_state("y")
        mc.add_transition("a", "x")
        mc.add_transition("x", "y")
        mc.add_transition("y", "x")  # livelock cycle, no progress label
        result = mc.check_liveness({"progress"})
        self.assertFalse(result.holds)
        self.assertEqual(result.counterexample.violated, "x")

    def test_empty_good_rejected(self):
        with self.assertRaises(ModelCheckerError):
            _triangle().check_liveness([])

    def test_deterministic_counterexample(self):
        def build():
            mc = ModelChecker()
            mc.add_state("a", initial=True)
            mc.add_state("stuck")
            mc.add_transition("a", "stuck")
            return mc

        r1 = build().check_liveness({"progress"})
        r2 = build().check_liveness({"progress"})
        self.assertEqual(
            r1.counterexample.states, r2.counterexample.states
        )


class TestRecords(unittest.TestCase):
    def test_trace_frozen_and_validated(self):
        t = Trace(states=("a", "b"), violated="b")
        with self.assertRaises(ModelCheckerError):
            Trace(states=("a", "b"), violated="a")  # violated must be last
        with self.assertRaises(ModelCheckerError):
            Trace(states=(), violated="a")
        d = t.as_dict()
        self.assertEqual(d["schema"], MODEL_CHECKER_SCHEMA)
        self.assertEqual(d["states"], ["a", "b"])

    def test_result_as_dict_shapes(self):
        r = _triangle().explore()
        d = r.as_dict()
        self.assertEqual(sorted(d["reachable"]), ["a", "b", "c"])
        s = _triangle().check_safety({"bad"})
        self.assertTrue(s.as_dict()["holds"])
        l = _triangle().check_liveness({"progress"})
        self.assertEqual(l.as_dict()["good_labels"], ["progress"])


class TestAudit(unittest.TestCase):
    def test_event_shape(self):
        ev = model_checker_audit_event("explored", 3, states=5)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "model-checker.explored")
        self.assertEqual(ev["module"], MODEL_CHECKER_SCHEMA)
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["states"], 5)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            model_checker_audit_event("nope", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            model_checker_audit_event("explored", -1)
        with self.assertRaises(ValueError):
            model_checker_audit_event("explored", True)

    def test_bad_field_type_rejected(self):
        with self.assertRaises(TypeError):
            model_checker_audit_event("explored", 0, data={"x": 1})


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import model_checker

        model_checker.main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
