"""Tests for property_tester (Hypothesis shaped, simulated)."""

import unittest

from property_tester import (
    AUDIT_SCHEMA,
    KIND_CHECKED,
    KIND_EXAMPLE,
    KIND_GIVEN,
    KIND_REJECTED,
    KIND_SHRUNK,
    PROPERTY_TESTER_SCHEMA,
    PROPERTY_TESTER_VERSION,
    STRATEGY_KINDS,
    BadPropertyError,
    BadStrategyError,
    BadValueError,
    ExampleRecord,
    GivenHandle,
    NotFailingError,
    PropertyTester,
    PropertyTesterError,
    SeqOrderError,
    ShrinkReport,
    Strategy,
    TestRun,
    UnknownCaseError,
    UnknownRunError,
    bools,
    dicts,
    floats,
    ints,
    just,
    lists,
    none,
    one_of,
    property_tester_audit_event,
    sampled_from,
    text,
    tuples,
)


def fresh(seed=b"test-seed") -> PropertyTester:
    return PropertyTester(seed=seed)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(PROPERTY_TESTER_VERSION, "property-tester.v1")
        self.assertEqual(PROPERTY_TESTER_SCHEMA, "northstar.property-tester.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        t = fresh()
        h = t.given(ints(), 1)
        self.assertIsInstance(h, GivenHandle)
        self.assertEqual(h.version, PROPERTY_TESTER_VERSION)
        self.assertEqual(h.schema, PROPERTY_TESTER_SCHEMA)
        self.assertTrue(h.digest.startswith("sha256:"))
        self.assertTrue(h.strategy_digest.startswith("sha256:"))

    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            (Path(__file__).resolve().parent.parent / "property_tester.py").read_text()
        )
        allowed = {
            "threading", "dataclasses", "typing", "__future__",
            "hashlib", "json", "canonical_json", "math",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_strategy_kinds_vocab(self):
        self.assertEqual(
            PropertyTester.strategy_kinds(),
            ("ints", "floats", "bools", "text", "lists", "sampled_from",
             "one_of", "tuples", "dicts", "none", "just"),
        )
        self.assertEqual(len(STRATEGY_KINDS), 11)


class TestStrategyConstructors(unittest.TestCase):
    def test_ints_bad_bounds(self):
        with self.assertRaises(BadStrategyError):
            ints(10, 5)
        with self.assertRaises(BadStrategyError):
            ints(True, 5)
        with self.assertRaises(BadStrategyError):
            ints(0, "5")

    def test_floats_bad_bounds(self):
        with self.assertRaises(BadStrategyError):
            floats(1.0, 0.0)
        with self.assertRaises(BadStrategyError):
            floats(float("nan"), 1.0)
        with self.assertRaises(BadStrategyError):
            floats(0.0, float("inf"))
        with self.assertRaises(BadStrategyError):
            floats(True, 1.0)

    def test_text_bad_args(self):
        with self.assertRaises(BadStrategyError):
            text(0, 4, "")
        with self.assertRaises(BadStrategyError):
            text(5, 2)
        with self.assertRaises(BadStrategyError):
            text(0, 1000)

    def test_sampled_from_bad(self):
        with self.assertRaises(BadStrategyError):
            sampled_from(())
        with self.assertRaises(BadStrategyError):
            sampled_from("abc")
        with self.assertRaises(PropertyTesterError):  # BadValueError subclass
            sampled_from([float("nan")])

    def test_one_of_tuples_bad(self):
        with self.assertRaises(BadStrategyError):
            one_of()
        with self.assertRaises(BadStrategyError):
            one_of(ints(), "nope")
        with self.assertRaises(BadStrategyError):
            tuples()
        with self.assertRaises(BadStrategyError):
            lists("nope")

    def test_just_bad_value(self):
        with self.assertRaises(BadValueError):
            just(float("inf"))
        with self.assertRaises(BadValueError):
            just({1, 2, 3})


class TestDraw(unittest.TestCase):
    def _drawn(self, strategy, n=50):
        t = fresh()
        h = t.given(strategy, 1)
        return [t.example(h.case_id, 2 + i).value for i in range(n)]

    def test_ints_draw_bounds(self):
        for v in self._drawn(ints(3, 7)):
            self.assertIsInstance(v, int)
            self.assertGreaterEqual(v, 3)
            self.assertLessEqual(v, 7)

    def test_draw_determinism(self):
        t1, t2 = fresh(), fresh()
        h1, h2 = t1.given(lists(ints(-5, 5), 0, 4), 1), t2.given(lists(ints(-5, 5), 0, 4), 1)
        for i in range(5):
            v1 = t1.example(h1.case_id, 2 + i).value
            v2 = t2.example(h2.case_id, 2 + i).value
            self.assertEqual(v1, v2)

    def test_text_draw_shape(self):
        alpha = "ab"
        for v in self._drawn(text(2, 5, alpha)):
            self.assertIsInstance(v, str)
            self.assertGreaterEqual(len(v), 2)
            self.assertLessEqual(len(v), 5)
            self.assertTrue(all(c in alpha for c in v))

    def test_lists_draw_shape(self):
        for v in self._drawn(lists(bools(), 1, 3), n=30):
            self.assertIsInstance(v, list)
            self.assertGreaterEqual(len(v), 1)
            self.assertLessEqual(len(v), 3)
            self.assertTrue(all(isinstance(x, bool) for x in v))

    def test_sampled_from_membership(self):
        vals = (10, 20, 30)
        for v in self._drawn(sampled_from(vals), n=30):
            self.assertIn(v, vals)

    def test_one_of_branch(self):
        seen_kinds = set()
        for v in self._drawn(one_of(ints(0, 0), text(1, 1, "z")), n=30):
            seen_kinds.add(type(v).__name__)
        self.assertEqual(seen_kinds, {"int", "str"})

    def test_tuples_dicts_shape(self):
        t = fresh()
        h = t.given(tuples(ints(), text(0, 2)), 1)
        v = t.example(h.case_id, 2).value
        self.assertIsInstance(v, tuple)
        self.assertEqual(len(v), 2)
        self.assertIsInstance(v[0], int)
        self.assertIsInstance(v[1], str)
        h2 = t.given(dicts(text(1, 2), ints(0, 9), 0, 3), 3)
        d = t.example(h2.case_id, 4).value
        self.assertIsInstance(d, dict)
        self.assertLessEqual(len(d), 3)

    def test_just_none_floats(self):
        t = fresh()
        h = t.given(just("fixed"), 1)
        self.assertEqual(t.example(h.case_id, 2).value, "fixed")
        h2 = t.given(none(), 3)
        self.assertIsNone(t.example(h2.case_id, 4).value)
        h3 = t.given(floats(-1.5, 1.5), 5)
        for i in range(20):
            v = t.example(h3.case_id, 6 + i).value
            self.assertGreaterEqual(v, -1.5)
            self.assertLessEqual(v, 1.5)


class TestGivenExample(unittest.TestCase):
    def test_given_registers(self):
        t = fresh()
        h1 = t.given(ints(), 1)
        h2 = t.given(text(), 2)
        self.assertEqual((h1.case_id, h2.case_id), ("case-1", "case-2"))
        self.assertEqual(t.case_ids(), ("case-1", "case-2"))
        self.assertEqual(t.case("case-1").strategy.kind, "ints")
        with self.assertRaises(UnknownCaseError):
            t.case("case-99")
        with self.assertRaises(BadStrategyError):
            t.given("not-a-strategy", 3)

    def test_example_record(self):
        t = fresh()
        h = t.given(bools(), 1)
        ex = t.example(h.case_id, 2)
        self.assertIsInstance(ex, ExampleRecord)
        self.assertTrue(ex.verify())
        self.assertEqual(ex.case_id, "case-1")
        self.assertTrue(ex.digest.startswith("sha256:"))
        with self.assertRaises(UnknownCaseError):
            t.example("case-99", 3)


class TestCheck(unittest.TestCase):
    def test_check_all_pass(self):
        t = fresh()
        h = t.given(ints(0, 10), 1)
        run = t.check(h.case_id, lambda x: 0 <= x <= 10, 2, max_examples=20)
        self.assertIsInstance(run, TestRun)
        self.assertTrue(run.passed)
        self.assertEqual(run.examples_run, 20)
        self.assertEqual(run.failures, ())
        self.assertEqual(t.run(run.run_id), run)

    def test_check_records_failure(self):
        t = fresh()
        h = t.given(ints(0, 100), 1)
        run = t.check(h.case_id, lambda x: x < 5, 2, max_examples=20)
        self.assertFalse(run.passed)
        self.assertGreater(len(run.failures), 0)
        self.assertLessEqual(len(run.failures), 5)
        for f in run.failures:
            self.assertTrue(f.digest.startswith("sha256:"))
            self.assertLessEqual(len(f.preview), 500)

    def test_check_exception_counts_as_failure(self):
        t = fresh()
        h = t.given(ints(0, 10), 1)

        def prop(x):
            if x > 5:
                raise ValueError("boom")
            return True

        run = t.check(h.case_id, prop, 2, max_examples=30)
        self.assertFalse(run.passed)

    def test_check_bad_inputs(self):
        t = fresh()
        h = t.given(ints(), 1)
        # note: failed mutations consume their seq (fail-closed ledger)
        with self.assertRaises(BadPropertyError):
            t.check(h.case_id, "not-callable", 2)
        with self.assertRaises(BadPropertyError):
            t.check(h.case_id, lambda x: True, 3, max_examples=0)
        with self.assertRaises(BadPropertyError):
            t.check(h.case_id, lambda x: True, 4, max_examples=10001)
        with self.assertRaises(UnknownCaseError):
            t.check("case-99", lambda x: True, 5)
        with self.assertRaises(UnknownRunError):
            t.run("run-99")


class TestShrink(unittest.TestCase):
    def test_shrink_ints(self):
        t = fresh()
        h = t.given(ints(0, 100), 1)
        rep = t.shrink(h.case_id, 100, lambda x: x < 10, 2)
        self.assertIsInstance(rep, ShrinkReport)
        self.assertEqual(rep.minimal, 10)
        self.assertTrue(rep.still_fails)
        self.assertGreater(rep.steps, 0)
        self.assertTrue(rep.minimal_digest.startswith("sha256:"))

    def test_shrink_lists(self):
        t = fresh()
        h = t.given(lists(ints(0, 9), 0, 6), 1)
        rep = t.shrink(h.case_id, [7, 8, 9, 1], lambda v: len(v) <= 2, 2)
        self.assertTrue(rep.still_fails)
        self.assertEqual(len(rep.minimal), 3)

    def test_shrink_text(self):
        t = fresh()
        h = t.given(text(0, 8, "abc"), 1)
        rep = t.shrink(h.case_id, "abcabc", lambda v: len(v) < 3, 2)
        self.assertTrue(rep.still_fails)
        self.assertEqual(len(rep.minimal), 3)

    def test_shrink_not_failing(self):
        t = fresh()
        h = t.given(ints(0, 100), 1)
        with self.assertRaises(NotFailingError):
            t.shrink(h.case_id, 5, lambda x: x < 10, 2)
        with self.assertRaises(BadValueError):
            t.shrink(h.case_id, float("nan"), lambda x: False, 3)
        with self.assertRaises(BadPropertyError):
            t.shrink(h.case_id, 50, "not-callable", 4)
        with self.assertRaises(UnknownCaseError):
            t.shrink("case-99", 50, lambda x: False, 5)


class TestSeq(unittest.TestCase):
    def test_seq_rewind(self):
        t = fresh()
        t.given(ints(), 1)
        with self.assertRaises(SeqOrderError):
            t.given(ints(), 1)
        with self.assertRaises(SeqOrderError):
            t.example("case-1", 1)

    def test_seq_bool_and_negative(self):
        t = fresh()
        with self.assertRaises(SeqOrderError):
            t.given(ints(), True)
        with self.assertRaises(SeqOrderError):
            t.given(ints(), -1)
        with self.assertRaises(SeqOrderError):
            t.given(ints(), "2")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        t = fresh()
        h = t.given(ints(0, 5), 1)
        t.example(h.case_id, 2)
        t.check(h.case_id, lambda x: True, 3, max_examples=5)
        t.shrink(h.case_id, 5, lambda x: x < 5, 4)
        kinds = [e["kind"] for e in t.audit_log()]
        self.assertEqual(
            kinds, [KIND_GIVEN, KIND_EXAMPLE, KIND_CHECKED, KIND_SHRUNK])
        for e in t.audit_log():
            self.assertEqual(e["schema"], AUDIT_SCHEMA)
            self.assertTrue(e["digest"].startswith("sha256:"))
        # values never cross the audit boundary
        blob = repr(t.audit_log())
        self.assertNotIn("preview", blob)

    def test_audit_bad_kind(self):
        with self.assertRaises(PropertyTesterError):
            property_tester_audit_event("nope", 1)
        with self.assertRaises(PropertyTesterError):
            property_tester_audit_event(KIND_GIVEN, 1, detail="nope")
        ev = property_tester_audit_event(KIND_REJECTED, 7, {"case_id": "case-1"})
        self.assertEqual(ev["kind"], KIND_REJECTED)
        self.assertEqual(ev["seq"], 7)


class TestMain(unittest.TestCase):
    def test_main(self):
        import property_tester as pt
        self.assertEqual(pt.main(), 0)


if __name__ == "__main__":
    unittest.main()
