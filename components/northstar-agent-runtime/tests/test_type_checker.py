"""Tests for type_checker.py (simply-typed lambda calculus, check/infer)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from type_checker import (
    App,
    ArrowType,
    BoolType,
    If,
    Lam,
    Let,
    LitBool,
    LitNat,
    NatType,
    TypeCheckError,
    TypeChecker,
    Var,
    TYPE_CHECKER_SCHEMA,
    TYPE_CHECKER_VERSION,
    free_vars,
    term_digest,
    term_to_str,
    type_checker_audit_event,
    type_to_str,
)


NAT = NatType()
BOOL = BoolType()


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TYPE_CHECKER_VERSION, "type-checker.v1")

    def test_schema_pin(self):
        self.assertEqual(TYPE_CHECKER_SCHEMA, "northstar.type-checker.v1")


class TestTypeConstruction(unittest.TestCase):
    def test_arrow_ok(self):
        t = ArrowType(NAT, BOOL)
        self.assertEqual(t.domain, NAT)
        self.assertEqual(t.codomain, BOOL)

    def test_arrow_rejects_non_type(self):
        with self.assertRaises(TypeCheckError):
            ArrowType("Nat", BOOL)
        with self.assertRaises(TypeCheckError):
            ArrowType(NAT, None)

    def test_types_frozen(self):
        t = ArrowType(NAT, BOOL)
        with self.assertRaises(Exception):
            t.domain = BOOL  # type: ignore[misc]

    def test_type_equality_structural(self):
        self.assertEqual(ArrowType(NAT, BOOL), ArrowType(NatType(), BoolType()))
        self.assertNotEqual(ArrowType(NAT, BOOL), ArrowType(BOOL, NAT))


class TestTermConstruction(unittest.TestCase):
    def test_var_rejects_empty_name(self):
        with self.assertRaises(TypeCheckError):
            Var("")

    def test_var_rejects_non_str(self):
        with self.assertRaises(TypeCheckError):
            Var(42)

    def test_litnat_rejects_bool(self):
        with self.assertRaises(TypeCheckError):
            LitNat(True)

    def test_litnat_rejects_negative(self):
        with self.assertRaises(TypeCheckError):
            LitNat(-1)

    def test_litbool_rejects_non_bool(self):
        with self.assertRaises(TypeCheckError):
            LitBool(1)

    def test_lam_rejects_unannotated(self):
        with self.assertRaises(TypeCheckError):
            Lam("x", "Nat", Var("x"))

    def test_terms_frozen(self):
        v = Var("x")
        with self.assertRaises(Exception):
            v.name = "y"  # type: ignore[misc]


class TestInfer(unittest.TestCase):
    def setUp(self):
        self.tc = TypeChecker()

    def test_infer_nat_literal(self):
        self.assertEqual(self.tc.infer(LitNat(0)), NAT)

    def test_infer_bool_literal(self):
        self.assertEqual(self.tc.infer(LitBool(False)), BOOL)

    def test_infer_unbound_var_raises(self):
        with self.assertRaises(TypeCheckError):
            self.tc.infer(Var("nope"))

    def test_infer_var_from_context(self):
        tc = TypeChecker({"x": BOOL})
        self.assertEqual(tc.infer(Var("x")), BOOL)

    def test_infer_identity(self):
        ident = Lam("x", NAT, Var("x"))
        self.assertEqual(self.tc.infer(ident), ArrowType(NAT, NAT))

    def test_infer_const(self):
        const = Lam("x", NAT, Lam("y", BOOL, Var("x")))
        self.assertEqual(
            self.tc.infer(const), ArrowType(NAT, ArrowType(BOOL, NAT))
        )

    def test_infer_application(self):
        ident = Lam("x", NAT, Var("x"))
        self.assertEqual(self.tc.infer(App(ident, LitNat(7))), NAT)

    def test_infer_nested_application(self):
        const = Lam("x", NAT, Lam("y", BOOL, Var("x")))
        term = App(App(const, LitNat(1)), LitBool(True))
        self.assertEqual(self.tc.infer(term), NAT)

    def test_infer_app_of_non_function_raises(self):
        with self.assertRaises(TypeCheckError):
            self.tc.infer(App(LitNat(1), LitNat(2)))

    def test_infer_app_domain_mismatch_raises(self):
        ident = Lam("x", NAT, Var("x"))
        with self.assertRaises(TypeCheckError):
            self.tc.infer(App(ident, LitBool(True)))

    def test_infer_if(self):
        term = If(LitBool(True), LitNat(1), LitNat(2))
        self.assertEqual(self.tc.infer(term), NAT)

    def test_infer_if_non_bool_cond_raises(self):
        with self.assertRaises(TypeCheckError):
            self.tc.infer(If(LitNat(0), LitNat(1), LitNat(2)))

    def test_infer_if_branch_mismatch_raises(self):
        with self.assertRaises(TypeCheckError):
            self.tc.infer(If(LitBool(True), LitNat(1), LitBool(False)))

    def test_infer_let(self):
        term = Let("x", LitNat(5), Var("x"))
        self.assertEqual(self.tc.infer(term), NAT)

    def test_infer_let_shadowing(self):
        tc = TypeChecker({"x": BOOL})
        term = Let("x", LitNat(5), Var("x"))
        self.assertEqual(tc.infer(term), NAT)
        # Outer context untouched.
        self.assertEqual(tc.infer(Var("x")), BOOL)

    def test_infer_rejects_non_term(self):
        with self.assertRaises(TypeCheckError):
            self.tc.infer("not a term")
        with self.assertRaises(TypeCheckError):
            self.tc.infer(None)


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.tc = TypeChecker()

    def test_check_identity_ok(self):
        ident = Lam("x", NAT, Var("x"))
        self.assertTrue(self.tc.check(ident, ArrowType(NAT, NAT)))

    def test_check_identity_wrong_type_false(self):
        ident = Lam("x", NAT, Var("x"))
        self.assertFalse(self.tc.check(ident, ArrowType(BOOL, BOOL)))
        self.assertFalse(self.tc.check(ident, NAT))

    def test_check_annotation_mismatch_false(self):
        # lam x:Bool. x checked against Nat -> Nat: annotation disagrees.
        term = Lam("x", BOOL, Var("x"))
        self.assertFalse(self.tc.check(term, ArrowType(NAT, NAT)))

    def test_check_literal(self):
        self.assertTrue(self.tc.check(LitNat(3), NAT))
        self.assertFalse(self.tc.check(LitNat(3), BOOL))

    def test_check_rejects_malformed_term(self):
        with self.assertRaises(TypeCheckError):
            self.tc.check("oops", NAT)

    def test_check_rejects_malformed_expected(self):
        with self.assertRaises(TypeCheckError):
            self.tc.check(LitNat(1), "Nat")


class TestContext(unittest.TestCase):
    def test_extend_returns_new_checker(self):
        tc = TypeChecker()
        tc2 = tc.extend("x", NAT)
        self.assertEqual(tc2.infer(Var("x")), NAT)
        with self.assertRaises(TypeCheckError):
            tc.infer(Var("x"))

    def test_constructor_rejects_bad_context(self):
        with self.assertRaises(TypeCheckError):
            TypeChecker({"x": "Nat"})
        with self.assertRaises(TypeCheckError):
            TypeChecker([("x", NAT)])  # type: ignore[arg-type]

    def test_context_property_is_copy(self):
        tc = TypeChecker({"x": NAT})
        ctx = tc.context
        ctx["y"] = BOOL
        with self.assertRaises(TypeCheckError):
            tc.infer(Var("y"))


class TestHelpers(unittest.TestCase):
    def test_type_to_str(self):
        self.assertEqual(type_to_str(NAT), "Nat")
        self.assertEqual(type_to_str(BOOL), "Bool")
        self.assertEqual(type_to_str(ArrowType(NAT, BOOL)), "Nat -> Bool")
        self.assertEqual(
            type_to_str(ArrowType(ArrowType(NAT, BOOL), NAT)),
            "(Nat -> Bool) -> Nat",
        )
        self.assertEqual(
            type_to_str(ArrowType(NAT, ArrowType(BOOL, NAT))),
            "Nat -> Bool -> Nat",
        )

    def test_term_to_str(self):
        self.assertEqual(term_to_str(LitNat(42)), "42")
        self.assertEqual(term_to_str(LitBool(True)), "true")
        self.assertEqual(term_to_str(Var("x")), "x")

    def test_free_vars(self):
        term = Lam("x", NAT, App(Var("x"), Var("y")))
        self.assertEqual(free_vars(term), frozenset({"y"}))
        self.assertEqual(free_vars(LitNat(1)), frozenset())
        self.assertEqual(
            free_vars(Let("x", Var("z"), Var("x"))), frozenset({"z"})
        )

    def test_term_digest_deterministic(self):
        a = Lam("x", NAT, Var("x"))
        b = Lam("x", NAT, Var("x"))
        c = Lam("x", BOOL, Var("x"))
        self.assertEqual(term_digest(a), term_digest(b))
        self.assertNotEqual(term_digest(a), term_digest(c))
        self.assertTrue(term_digest(a).startswith("sha256:"))

    def test_term_digest_distinguishes_structure(self):
        # if true then 1 else 2  vs  if true then 2 else 1
        a = If(LitBool(True), LitNat(1), LitNat(2))
        b = If(LitBool(True), LitNat(2), LitNat(1))
        self.assertNotEqual(term_digest(a), term_digest(b))


class TestAuditEvent(unittest.TestCase):
    def setUp(self):
        self.term = Lam("x", NAT, Var("x"))

    def test_shape(self):
        ev = type_checker_audit_event("inferred", self.term, 3, result="Nat -> Nat")
        self.assertEqual(ev["schema"], TYPE_CHECKER_SCHEMA)
        self.assertEqual(ev["kind"], "inferred")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["term_digest"], term_digest(self.term))
        self.assertEqual(ev["result"], "Nat -> Nat")
        self.assertEqual(ev["version"], TYPE_CHECKER_VERSION)

    def test_all_kinds(self):
        for kind in ("inferred", "checked", "check-failed", "infer-failed"):
            ev = type_checker_audit_event(kind, self.term, 0)
            self.assertEqual(ev["kind"], kind)

    def test_bad_kind_rejected(self):
        with self.assertRaises(TypeCheckError):
            type_checker_audit_event("nope", self.term, 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeCheckError):
            type_checker_audit_event("checked", self.term, -1)
        with self.assertRaises(TypeCheckError):
            type_checker_audit_event("checked", self.term, True)

    def test_bad_result_rejected(self):
        with self.assertRaises(TypeCheckError):
            type_checker_audit_event("checked", self.term, 0, result=42)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import type_checker as mod

        # Should not raise; prints one line.
        mod.main()


if __name__ == "__main__":
    unittest.main()
