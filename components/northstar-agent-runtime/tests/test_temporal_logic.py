"""Tests for temporal_logic.py: LTL over finite traces (LTLf semantics)."""

import dataclasses
import unittest

from temporal_logic import (
    Always,
    And,
    Atom,
    Eventually,
    Formula,
    Implies,
    Next,
    Not,
    Or,
    ParseError,
    Release,
    TFalse,
    TTrue,
    TemporalLogic,
    TemporalLogicError,
    TraceVerdict,
    Until,
    WeakNext,
    coerce_trace,
    formula_pin,
    parse_formula,
    temporal_logic_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        import temporal_logic as m

        self.assertEqual(m.TEMPORAL_LOGIC_VERSION, "temporal-logic.v1")
        self.assertEqual(m.TEMPORAL_LOGIC_SCHEMA, "northstar.temporal-logic.v1")


class TestFormulaConstruction(unittest.TestCase):
    def test_atom_validation(self):
        with self.assertRaises(TemporalLogicError):
            Atom("")
        with self.assertRaises(TemporalLogicError):
            Atom(True)
        with self.assertRaises(TemporalLogicError):
            Atom(123)
        self.assertEqual(Atom("p").name, "p")

    def test_operator_type_validation(self):
        with self.assertRaises(TemporalLogicError):
            Not("p")  # must be a Formula, not a bare name
        with self.assertRaises(TemporalLogicError):
            And(Atom("a"), "b")
        with self.assertRaises(TemporalLogicError):
            TemporalLogic("p")  # constructor takes a Formula

    def test_combinators_accept_formula_or_name(self):
        self.assertEqual(TemporalLogic.always("p"), Always(Atom("p")))
        self.assertEqual(TemporalLogic.eventually(Atom("p")), Eventually(Atom("p")))
        self.assertEqual(TemporalLogic.until("a", "b"), Until(Atom("a"), Atom("b")))
        self.assertEqual(TemporalLogic.next("p"), Next(Atom("p")))
        self.assertEqual(TemporalLogic.weak_next("p"), WeakNext(Atom("p")))
        self.assertEqual(TemporalLogic.release("a", "b"), Release(Atom("a"), Atom("b")))
        self.assertEqual(TemporalLogic.atom("p"), Atom("p"))

    def test_combinators_reject_bad_input(self):
        with self.assertRaises(TemporalLogicError):
            TemporalLogic.always(None)
        with self.assertRaises(TemporalLogicError):
            TemporalLogic.until("a", 42)
        with self.assertRaises(TemporalLogicError):
            TemporalLogic.eventually(True)

    def test_dunder_operators(self):
        a, b = Atom("a"), Atom("b")
        self.assertEqual(a & b, And(a, b))
        self.assertEqual(a | b, Or(a, b))
        self.assertEqual(~a, Not(a))
        self.assertEqual(a.implies(b), Implies(a, b))

    def test_formulas_are_frozen(self):
        a = Atom("p")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            a.name = "q"  # type: ignore[misc]

    def test_verdict_is_frozen(self):
        v = TraceVerdict(formula="p", formula_pin="sha256:x", holds=True, trace_length=1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            v.holds = False  # type: ignore[misc]


class TestTraceValidation(unittest.TestCase):
    def test_empty_trace_refused(self):
        tl = TemporalLogic(Atom("p"))
        with self.assertRaises(TemporalLogicError):
            tl.check([])

    def test_bad_trace_type_refused(self):
        tl = TemporalLogic(Atom("p"))
        with self.assertRaises(TemporalLogicError):
            tl.check("p")

    def test_bad_state_type_refused(self):
        tl = TemporalLogic(Atom("p"))
        with self.assertRaises(TemporalLogicError):
            tl.check([{"p": True}])

    def test_bad_proposition_refused(self):
        tl = TemporalLogic(Atom("p"))
        with self.assertRaises(TemporalLogicError):
            tl.check([[1, 2]])
        with self.assertRaises(TemporalLogicError):
            tl.check([[""]])
        with self.assertRaises(TemporalLogicError):
            tl.check([[True]])

    def test_state_containers_accepted(self):
        tl = TemporalLogic(Atom("p"))
        self.assertTrue(tl.check([{"p"}]))
        self.assertTrue(tl.check([frozenset({"p"})]))
        self.assertTrue(tl.check([["p"]]))
        self.assertTrue(tl.check([("p",)]))

    def test_coerce_trace(self):
        states = coerce_trace([{"a"}, ["b"]])
        self.assertEqual(states, (frozenset({"a"}), frozenset({"b"})))


class TestBooleanOperators(unittest.TestCase):
    def test_constants(self):
        self.assertTrue(TemporalLogic(TTrue()).check([set()]))
        self.assertFalse(TemporalLogic(TFalse()).check([set()]))

    def test_atom(self):
        tl = TemporalLogic(Atom("p"))
        self.assertTrue(tl.check([{"p", "q"}]))
        self.assertFalse(tl.check([{"q"}]))

    def test_not_and_or_implies(self):
        a, b = Atom("a"), Atom("b")
        self.assertTrue(TemporalLogic(Not(a)).check([set()]))
        self.assertFalse(TemporalLogic(Not(a)).check([{"a"}]))
        self.assertTrue(TemporalLogic(And(a, b)).check([{"a", "b"}]))
        self.assertFalse(TemporalLogic(And(a, b)).check([{"a"}]))
        self.assertTrue(TemporalLogic(Or(a, b)).check([{"b"}]))
        self.assertFalse(TemporalLogic(Or(a, b)).check([set()]))
        self.assertTrue(TemporalLogic(Implies(a, b)).check([set()]))  # vacuously true
        self.assertFalse(TemporalLogic(Implies(a, b)).check([{"a"}]))
        self.assertTrue(TemporalLogic(Implies(a, b)).check([{"a", "b"}]))


class TestTemporalOperators(unittest.TestCase):
    def test_always(self):
        tl = TemporalLogic(Always(Atom("p")))
        self.assertTrue(tl.check([{"p"}, {"p"}]))
        self.assertFalse(tl.check([{"p"}, set()]))

    def test_eventually(self):
        tl = TemporalLogic(Eventually(Atom("p")))
        self.assertTrue(tl.check([set(), {"p"}]))
        self.assertFalse(tl.check([set(), set()]))

    def test_until_happy(self):
        tl = TemporalLogic(Until(Atom("a"), Atom("b")))
        self.assertTrue(tl.check([{"a"}, {"a"}, {"b"}]))
        self.assertTrue(tl.check([{"b"}]))  # psi immediately: vacuous left side

    def test_until_psi_never(self):
        tl = TemporalLogic(Until(Atom("a"), Atom("b")))
        self.assertFalse(tl.check([{"a"}, {"a"}]))

    def test_until_left_breaks(self):
        tl = TemporalLogic(Until(Atom("a"), Atom("b")))
        self.assertFalse(tl.check([{"a"}, set(), {"b"}]))

    def test_strong_next(self):
        tl = TemporalLogic(Next(Atom("p")))
        self.assertTrue(tl.check([set(), {"p"}]))
        self.assertFalse(tl.check([{"p"}, set()]))
        self.assertFalse(tl.check([{"p"}]))  # false at trace end

    def test_weak_next(self):
        tl = TemporalLogic(WeakNext(Atom("p")))
        self.assertTrue(tl.check([set(), {"p"}]))
        self.assertTrue(tl.check([set()]))  # true at trace end

    def test_release(self):
        # a R b: b holds up to and including the first a
        tl = TemporalLogic(Release(Atom("a"), Atom("b")))
        self.assertTrue(tl.check([{"b"}, {"a", "b"}]))
        self.assertTrue(tl.check([{"b"}, {"b"}]))  # b everywhere, no a: holds
        self.assertFalse(tl.check([set(), {"a", "b"}]))  # b missing before a

    def test_response_pattern(self):
        # G (request -> F grant): every request is eventually granted
        tl = TemporalLogic.parse("G (request -> F grant)")
        self.assertTrue(tl.check([{"request"}, set(), {"grant"}]))
        self.assertFalse(tl.check([{"request"}, set(), set()]))
        self.assertTrue(tl.check([set(), set()]))  # vacuous

    def test_safety_pattern(self):
        # G !(crit_a && crit_b): mutual exclusion
        tl = TemporalLogic.parse("G !(crit_a && crit_b)")
        self.assertTrue(tl.check([{"crit_a"}, {"crit_b"}, set()]))
        self.assertFalse(tl.check([{"crit_a", "crit_b"}]))


class TestParser(unittest.TestCase):
    def test_all_operators(self):
        f = parse_formula("G F X W p U q R r && s || t -> u")
        self.assertIsInstance(f, Implies)

    def test_precedence_and_over_or(self):
        f = parse_formula("a && b || c")
        self.assertEqual(f, Or(And(Atom("a"), Atom("b")), Atom("c")))

    def test_temporal_binds_tighter_than_and(self):
        f = parse_formula("a && b U c")
        self.assertEqual(f, And(Atom("a"), Until(Atom("b"), Atom("c"))))

    def test_implies_right_associative(self):
        f = parse_formula("a -> b -> c")
        self.assertEqual(f, Implies(Atom("a"), Implies(Atom("b"), Atom("c"))))

    def test_parens(self):
        f = parse_formula("(a || b) && c")
        self.assertEqual(f, And(Or(Atom("a"), Atom("b")), Atom("c")))

    def test_round_trip(self):
        texts = [
            "G (request -> F grant)",
            "a U b",
            "G !(x && y)",
            "X p -> W q",
            "a R b",
            "!true",
            "(a -> b) && (c || !d)",
        ]
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual(parse_formula(str(parse_formula(text))), parse_formula(text))

    def test_str_shape(self):
        self.assertEqual(str(parse_formula("G (a -> F b)")), "G (a -> F b)")
        self.assertEqual(str(parse_formula("a && b || c")), "a && b || c")
        self.assertEqual(str(TemporalLogic.always("p")), "G p")

    def test_parse_errors(self):
        for bad in ["", "   ", "a b", "(a", "a)", "()", "a &&& b", "a @ b", "a ->"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ParseError):
                    parse_formula(bad)

    def test_parse_non_string_refused(self):
        with self.assertRaises(ParseError):
            parse_formula(None)  # type: ignore[arg-type]
        with self.assertRaises(ParseError):
            parse_formula(42)  # type: ignore[arg-type]

    def test_class_parse(self):
        tl = TemporalLogic.parse("F done")
        self.assertIsInstance(tl, TemporalLogic)
        self.assertTrue(tl.check([set(), {"done"}]))


class TestPinsAndRecords(unittest.TestCase):
    def test_pin_determinism_and_shape(self):
        p1 = formula_pin(parse_formula("G (a -> F b)"))
        p2 = formula_pin(parse_formula("G (a -> F b)"))
        self.assertEqual(p1, p2)
        self.assertTrue(p1.startswith("sha256:"))
        self.assertNotEqual(p1, formula_pin(parse_formula("G (a -> F c)")))

    def test_pin_rejects_non_formula(self):
        with self.assertRaises(TemporalLogicError):
            formula_pin("G p")  # type: ignore[arg-type]

    def test_formula_as_dict(self):
        d = parse_formula("F done").as_dict()
        self.assertEqual(d["schema"], "northstar.temporal-logic.v1")
        self.assertEqual(d["version"], "temporal-logic.v1")
        self.assertEqual(d["formula"], "F done")
        self.assertTrue(d["pin"].startswith("sha256:"))

    def test_verdict_shape(self):
        tl = TemporalLogic.parse("G p")
        v = tl.verdict([{"p"}, set()])
        self.assertIsInstance(v, TraceVerdict)
        self.assertFalse(v.holds)
        self.assertEqual(v.trace_length, 2)
        d = v.as_dict()
        self.assertEqual(d["formula"], "G p")
        self.assertFalse(d["holds"])
        self.assertEqual(d["trace_length"], 2)

    def test_verdict_pass(self):
        v = TemporalLogic.parse("F p").verdict([set(), {"p"}])
        self.assertTrue(v.holds)


class TestAuditEvents(unittest.TestCase):
    def test_shapes(self):
        tl = TemporalLogic.parse("G p")
        ev = temporal_logic_audit_event("parsed", tl, 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "temporal-logic.parsed")
        self.assertEqual(ev["module"], "northstar.temporal-logic.v1")
        self.assertEqual(ev["version"], "temporal-logic.v1")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["formula"], "G p")
        self.assertTrue(ev["formula_pin"].startswith("sha256:"))
        ev2 = temporal_logic_audit_event("checked", tl, 0)
        self.assertEqual(ev2["kind"], "temporal-logic.checked")

    def test_rejections(self):
        tl = TemporalLogic.parse("G p")
        with self.assertRaises(ValueError):
            temporal_logic_audit_event("nope", tl, 0)
        with self.assertRaises(TypeError):
            temporal_logic_audit_event("parsed", "G p", 0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            temporal_logic_audit_event("parsed", tl, -1)
        with self.assertRaises(ValueError):
            temporal_logic_audit_event("parsed", tl, True)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import temporal_logic as m

        m.main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
