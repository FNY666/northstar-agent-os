"""Tests for hoare_logic: triples, proof rules, and VCG."""

import unittest

import hoare_logic as HL
from hoare_logic import (
    Assign,
    Assertion,
    Atom,
    HoareLogic,
    HoareLogicError,
    HoareTriple,
    If,
    LinExpr,
    RuleApplicationError,
    Seq,
    Skip,
    While,
    implies,
    substitute,
)


def A(*atoms):
    return Assertion.of(list(atoms))


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(HL.HOARE_LOGIC_VERSION, "hoare-logic.v1")
        self.assertEqual(HL.HOARE_LOGIC_SCHEMA, "northstar.hoare-logic.v1")

    def test_triple_digest_shape(self):
        t = HoareTriple(A(Atom("x", "==", 0)), Skip(), A(Atom("x", "==", 0)))
        self.assertTrue(t.digest().startswith("sha256:"))
        self.assertEqual(t.as_dict()["schema"], "northstar.hoare-logic.v1")


class TestValidation(unittest.TestCase):
    def test_bool_int_rejected(self):
        with self.assertRaises(HoareLogicError):
            Atom("x", "==", True)
        with self.assertRaises(HoareLogicError):
            LinExpr(True, "x", 0)

    def test_bad_relation_rejected(self):
        with self.assertRaises(HoareLogicError):
            Atom("x", "===", 0)

    def test_empty_var_rejected(self):
        with self.assertRaises(HoareLogicError):
            Atom("", "==", 0)
        with self.assertRaises(HoareLogicError):
            Assign("", LinExpr(0, None, 1))

    def test_if_cond_must_be_atom(self):
        with self.assertRaises(HoareLogicError):
            If(A(Atom("x", "==", 0)), Skip(), Skip())

    def test_while_inv_must_be_assertion(self):
        with self.assertRaises(HoareLogicError):
            While(Atom("x", "<", 1), Atom("x", ">=", 0), Skip())

    def test_atom_negation(self):
        self.assertEqual(Atom("x", "<", 5).negate(), Atom("x", ">=", 5))
        self.assertEqual(Atom("y", "!=", 2).negate(), Atom("y", "==", 2))


class TestImplies(unittest.TestCase):
    def test_trivial(self):
        self.assertTrue(implies(A(Atom("x", "==", 3)), A(Atom("x", "==", 3))))

    def test_bounds_entail(self):
        hyps = A(Atom("x", ">=", 0), Atom("x", "<=", 5))
        self.assertTrue(implies(hyps, A(Atom("x", ">", -1))))
        self.assertTrue(implies(hyps, A(Atom("x", "<", 6))))
        self.assertFalse(implies(hyps, A(Atom("x", ">=", 6))))

    def test_strict_bounds_integer(self):
        hyps = A(Atom("x", ">", 0))
        self.assertTrue(implies(hyps, A(Atom("x", ">=", 1))))
        self.assertTrue(implies(hyps, A(Atom("x", "!=", 0))))

    def test_disequality_from_interval(self):
        hyps = A(Atom("x", ">=", 10))
        self.assertTrue(implies(hyps, A(Atom("x", "!=", 3))))
        self.assertFalse(implies(hyps, A(Atom("x", "!=", 10))))

    def test_equality_collapses_interval(self):
        hyps = A(Atom("x", ">=", 2), Atom("x", "<=", 2))
        self.assertTrue(implies(hyps, A(Atom("x", "==", 2))))

    def test_contradiction_entails_all(self):
        hyps = A(Atom("x", "==", 1), Atom("x", "==", 2))
        self.assertTrue(implies(hyps, A(Atom("y", "==", 99))))

    def test_missing_info_fails(self):
        self.assertFalse(implies(A(Atom("x", "==", 1)), A(Atom("y", "==", 1))))
        self.assertFalse(implies(HL.TRUE, A(Atom("x", ">=", 0))))

    def test_bad_types_raise(self):
        with self.assertRaises(HoareLogicError):
            implies("nope", HL.TRUE)


class TestSubstitute(unittest.TestCase):
    def test_simple_shift(self):
        post = A(Atom("x", ">=", 1))
        got = substitute(post, "x", LinExpr(1, "x", 1))
        self.assertEqual(got, A(Atom("x", ">=", 0)))

    def test_equality_divisible(self):
        post = A(Atom("x", "==", 4))
        got = substitute(post, "x", LinExpr(2, "x", 0))
        self.assertEqual(got, A(Atom("x", "==", 2)))

    def test_equality_indivisible_is_false(self):
        post = A(Atom("x", "==", 3))
        got = substitute(post, "x", LinExpr(2, "x", 0))
        self.assertIsInstance(got, HL._FalseAssertion)

    def test_negative_coeff_flips(self):
        post = A(Atom("x", "<", 5))
        got = substitute(post, "x", LinExpr(-1, "x", 10))
        # -x + 10 < 5  <=>  x > 5
        self.assertEqual(got, A(Atom("x", ">", 5)))

    def test_constant_assignment(self):
        post = A(Atom("x", "==", 7), Atom("y", ">=", 0))
        got = substitute(post, "x", LinExpr(0, None, 7))
        self.assertEqual(got, A(Atom("y", ">=", 0)))

    def test_other_vars_untouched(self):
        post = A(Atom("y", "==", 2))
        self.assertEqual(substitute(post, "x", LinExpr(1, "x", 1)), post)


class TestVCG(unittest.TestCase):
    def setUp(self):
        self.hl = HoareLogic()

    def test_assign_triple(self):
        check = self.hl.triple(A(Atom("x", "==", 0)),
                               Assign("x", LinExpr(1, "x", 1)),
                               A(Atom("x", "==", 1)))
        self.assertTrue(check.verified)

    def test_assign_triple_fails(self):
        check = self.hl.triple(A(Atom("x", "==", 0)),
                               Assign("x", LinExpr(1, "x", 1)),
                               A(Atom("x", "==", 2)))
        self.assertFalse(check.verified)
        self.assertEqual(len(check.failed), 1)

    def test_skip_triple(self):
        q = A(Atom("x", ">=", 0))
        check = self.hl.triple(q, Skip(), q)
        self.assertTrue(check.verified)

    def test_seq_triple(self):
        prog = Seq(Assign("x", LinExpr(0, None, 1)),
                   Assign("y", LinExpr(1, "x", 0)))
        check = self.hl.triple(HL.TRUE, prog, A(Atom("y", "==", 1)))
        self.assertTrue(check.verified)

    def test_if_triple(self):
        prog = If(Atom("x", ">", 0),
                  Assign("y", LinExpr(0, None, 1)),
                  Assign("y", LinExpr(0, None, -1)))
        check = self.hl.triple(HL.TRUE, prog,
                               A(Atom("y", ">=", -1), Atom("y", "<=", 1)))
        self.assertTrue(check.verified)

    def test_while_triple(self):
        inv = A(Atom("x", ">=", 0))
        prog = While(Atom("x", "<", 10), inv, Assign("x", LinExpr(1, "x", 1)))
        check = self.hl.triple(inv, prog, A(Atom("x", ">=", 10)))
        self.assertTrue(check.verified)

    def test_while_bad_invariant_fails(self):
        inv = A(Atom("x", ">=", 100))
        prog = While(Atom("x", "<", 10), inv, Assign("x", LinExpr(1, "x", 1)))
        check = self.hl.triple(A(Atom("x", ">=", 0)), prog, inv)
        self.assertFalse(check.verified)


class TestRules(unittest.TestCase):
    def setUp(self):
        self.hl = HoareLogic()

    def test_skip_axiom(self):
        q = A(Atom("x", "==", 5))
        check = self.hl.skip_axiom(q)
        self.assertTrue(check.verified)
        self.assertEqual(check.proof.rule, "skip-axiom")

    def test_assign_axiom(self):
        check = self.hl.assign_axiom("x", LinExpr(1, "x", 1),
                                     A(Atom("x", "==", 1)))
        self.assertTrue(check.verified)
        self.assertEqual(check.triple.pre, A(Atom("x", "==", 0)))

    def test_sequence_rule(self):
        t1 = self.hl.assign_axiom("x", LinExpr(0, None, 1),
                                  A(Atom("x", "==", 1)))
        t2 = self.hl.assign_axiom("y", LinExpr(1, "x", 0),
                                  A(Atom("y", "==", 1)))
        # t1.post is {x==1}; t2.pre needs {x==1} - rebuild t2 accordingly
        t2b = self.hl.triple(A(Atom("x", "==", 1)),
                             Assign("y", LinExpr(1, "x", 0)),
                             A(Atom("y", "==", 1), Atom("x", "==", 1)))
        self.assertTrue(t2b.verified)
        seq = self.hl.sequence_rule(t1, t2b)
        self.assertTrue(seq.verified)
        self.assertIsInstance(seq.triple.prog, Seq)
        self.assertEqual(seq.proof.rule, "sequence")

    def test_sequence_rule_middle_mismatch(self):
        t1 = self.hl.assign_axiom("x", LinExpr(0, None, 1),
                                  A(Atom("x", "==", 1)))
        t2 = self.hl.assign_axiom("x", LinExpr(0, None, 9),
                                  A(Atom("x", "==", 9)))
        with self.assertRaises(RuleApplicationError):
            self.hl.sequence_rule(t1, t2)

    def test_sequence_rule_unverified_premise(self):
        bad = self.hl.triple(A(Atom("x", "==", 0)),
                             Assign("x", LinExpr(1, "x", 1)),
                             A(Atom("x", "==", 99)))
        good = self.hl.skip_axiom(HL.TRUE)
        with self.assertRaises(RuleApplicationError):
            self.hl.sequence_rule(bad, good)

    def test_loop_rule(self):
        inv = A(Atom("x", ">=", 0))
        cond = Atom("x", "<", 10)
        body = self.hl.triple(inv.conjoin(cond),
                              Assign("x", LinExpr(1, "x", 1)), inv)
        self.assertTrue(body.verified)
        loop = self.hl.loop_rule(body, inv, cond, A(Atom("x", ">=", 10)))
        self.assertTrue(loop.verified)
        self.assertIsInstance(loop.triple.prog, While)

    def test_loop_rule_bad_exit(self):
        inv = A(Atom("x", ">=", 0))
        cond = Atom("x", "<", 10)
        body = self.hl.triple(inv.conjoin(cond),
                              Assign("x", LinExpr(1, "x", 1)), inv)
        with self.assertRaises(RuleApplicationError):
            self.hl.loop_rule(body, inv, cond, A(Atom("x", "==", 10)))

    def test_if_rule(self):
        cond = Atom("x", ">", 0)
        pre = HL.TRUE
        then = self.hl.triple(pre.conjoin(cond),
                              Assign("y", LinExpr(0, None, 1)),
                              A(Atom("y", "==", 1)))
        els = self.hl.triple(pre.conjoin(cond.negate()),
                             Assign("y", LinExpr(0, None, 1)),
                             A(Atom("y", "==", 1)))
        check = self.hl.if_rule(then, els, cond, pre)
        self.assertTrue(check.verified)
        self.assertIsInstance(check.triple.prog, If)

    def test_consequence_rule(self):
        base = self.hl.triple(A(Atom("x", ">=", 0)),
                              Assign("x", LinExpr(1, "x", 1)),
                              A(Atom("x", ">=", 1)))
        self.assertTrue(base.verified)
        weak = self.hl.consequence_rule(base, A(Atom("x", ">=", 5)),
                                        A(Atom("x", ">", 0)))
        self.assertTrue(weak.verified)

    def test_consequence_rule_rejects_bad_strengthening(self):
        base = self.hl.triple(A(Atom("x", ">=", 0)),
                              Assign("x", LinExpr(1, "x", 1)),
                              A(Atom("x", ">=", 1)))
        # {x >= -5} does NOT imply {x >= 0}: invalid pre-strengthening.
        with self.assertRaises(RuleApplicationError):
            self.hl.consequence_rule(base, A(Atom("x", ">=", -5)),
                                     A(Atom("x", ">=", 1)))
        # {x >= 1} does NOT follow from {x >= 1}... post must be implied by
        # old post: {x >= 100} is not implied by {x >= 1}.
        with self.assertRaises(RuleApplicationError):
            self.hl.consequence_rule(base, A(Atom("x", ">=", 0)),
                                     A(Atom("x", ">=", 100)))

    def test_proof_tree_recorded(self):
        t1 = self.hl.assign_axiom("x", LinExpr(0, None, 1),
                                  A(Atom("x", "==", 1)))
        t2 = self.hl.triple(A(Atom("x", "==", 1)),
                            Assign("y", LinExpr(1, "x", 0)),
                            A(Atom("y", "==", 1), Atom("x", "==", 1)))
        seq = self.hl.sequence_rule(t1, t2)
        self.assertEqual(len(seq.proof.premises), 2)
        self.assertEqual(seq.proof.triple_digest, seq.triple.digest())


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.hl = HoareLogic()

    def test_audit_event_shape(self):
        check = self.hl.triple(A(Atom("x", "==", 0)),
                               Assign("x", LinExpr(1, "x", 1)),
                               A(Atom("x", "==", 1)))
        ev = self.hl.hoare_logic_audit_event("triple-checked", 3, check)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "hoare-logic.triple-checked")
        self.assertEqual(ev["module"], "northstar.hoare-logic.v1")
        self.assertEqual(ev["triple_digest"], check.triple.digest())

    def test_audit_bad_kind_rejected(self):
        with self.assertRaises(HoareLogicError):
            self.hl.hoare_logic_audit_event("bogus", 0)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(HoareLogicError):
            self.hl.hoare_logic_audit_event("triple-checked", -1)
        with self.assertRaises(HoareLogicError):
            self.hl.hoare_logic_audit_event("triple-checked", True)

    def test_main(self):
        HL.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
