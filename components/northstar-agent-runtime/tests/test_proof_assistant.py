"""Tests for proof_assistant.py (interactive theorem proving, simulated)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proof_assistant import (
    And_,
    App,
    Eq,
    Exists,
    Expr,
    ForAll,
    Imp,
    Or_,
    PROOF_ASSISTANT_SCHEMA,
    PROOF_ASSISTANT_VERSION,
    ProofAssistant,
    ProofCertificate,
    ProofError,
    TacticRecord,
    Var,
    parse_expr,
    print_expr,
    proof_assistant_audit_event,
    rewrite_in,
    subst,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PROOF_ASSISTANT_VERSION, "proof-assistant.v1")

    def test_schema_pin(self):
        self.assertEqual(PROOF_ASSISTANT_SCHEMA, "northstar.proof-assistant.v1")


class TestParser(unittest.TestCase):
    def test_atom(self):
        self.assertEqual(parse_expr("A"), Var("A"))

    def test_imp_right_assoc(self):
        self.assertEqual(parse_expr("A -> B -> C"), Imp(Var("A"), Imp(Var("B"), Var("C"))))

    def test_and_binds_tighter_than_imp(self):
        self.assertEqual(parse_expr("A /\\ B -> C"), Imp(And_(Var("A"), Var("B")), Var("C")))

    def test_or_lowest(self):
        self.assertEqual(parse_expr("A -> B \\/ C"), Imp(Var("A"), Or_(Var("B"), Var("C"))))

    def test_eq(self):
        self.assertEqual(parse_expr("x = y"), Eq(Var("x"), Var("y")))

    def test_forall(self):
        self.assertEqual(parse_expr("forall x, P x"), ForAll("x", App(Var("P"), Var("x"))))

    def test_exists(self):
        self.assertEqual(parse_expr("exists x, P x"), Exists("x", App(Var("P"), Var("x"))))

    def test_app_juxtaposition(self):
        self.assertEqual(parse_expr("f x y"), App(App(Var("f"), Var("x")), Var("y")))

    def test_round_trip(self):
        for s in ("A -> B -> A", "P x /\\ Q y", "(A \\/ B) -> C", "forall x, P x",
                  "x = y", "(f x) = (g y)"):
            self.assertEqual(parse_expr(print_expr(parse_expr(s))), parse_expr(s), s)

    def test_bad_syntax_rejected(self):
        for bad in ("", "   ", "A ->", "(A", "A)", "A B ->", "-> A", "forall , P"):
            with self.assertRaises(ProofError, msg=bad):
                parse_expr(bad)

    def test_bad_type_rejected(self):
        for bad in (None, 123, True, b"A"):
            with self.assertRaises(ProofError):
                parse_expr(bad)

    def test_print_needs_expr(self):
        with self.assertRaises(ProofError):
            print_expr("A")


class TestSubstRewrite(unittest.TestCase):
    def test_subst_basic(self):
        self.assertEqual(subst(parse_expr("P x"), "x", Var("y")), parse_expr("P y"))

    def test_subst_shadowed(self):
        e = parse_expr("forall x, P x")
        self.assertEqual(subst(e, "x", Var("y")), e)

    def test_rewrite_in(self):
        goal = parse_expr("P x /\\ Q x")
        new = rewrite_in(goal, Var("x"), Var("y"))
        self.assertEqual(new, parse_expr("P y /\\ Q y"))

    def test_rewrite_in_no_match_identity(self):
        goal = parse_expr("P y")
        self.assertEqual(rewrite_in(goal, Var("x"), Var("z")), goal)


class TestIntro(unittest.TestCase):
    def test_intro_moves_antecedent(self):
        pa = ProofAssistant().goal("A -> B")
        pa.intro("hA")
        self.assertEqual(pa.hypotheses()["hA"], Var("A"))
        self.assertEqual(pa.goals(), (Var("B"),))

    def test_intro_auto_name(self):
        pa = ProofAssistant().goal("A -> B")
        pa.intro()
        self.assertIn("H0", pa.hypotheses())

    def test_intro_duplicate_name_rejected(self):
        pa = ProofAssistant().goal("A -> B -> C")
        pa.intro("h")
        with self.assertRaises(ProofError):
            pa.intro("h")

    def test_intro_non_imp_rejected(self):
        pa = ProofAssistant().goal("A /\\ B")
        with self.assertRaises(ProofError):
            pa.intro()

    def test_intro_forall_fresh_param(self):
        pa = ProofAssistant().goal("forall x, P x")
        pa.intro()
        (g,) = pa.goals()
        self.assertEqual(g, App(Var("P"), Var("x_0")))

    def test_intro_no_goal_rejected(self):
        pa = ProofAssistant()
        with self.assertRaises(ProofError):
            pa.intro()


class TestApply(unittest.TestCase):
    def test_apply_exact_closes(self):
        pa = ProofAssistant().goal("A -> A")
        pa.intro("h")
        pa.apply("h")
        self.assertEqual(pa.goals(), ())

    def test_apply_modus_ponens(self):
        pa = ProofAssistant().goal("(A -> B) -> A -> B")
        pa.intro("himp").intro("hA")
        pa.apply("himp")
        self.assertEqual(pa.goals(), (Var("A"),))

    def test_apply_curried(self):
        pa = ProofAssistant().goal("(A -> B -> C) -> A -> B -> C")
        pa.intro("h").intro("ha").intro("hb")
        pa.apply("h")
        self.assertEqual(pa.goals(), (Var("B"), Var("A")))

    def test_apply_mismatch_rejected(self):
        pa = ProofAssistant().goal("A -> B")
        pa.intro("hA")
        with self.assertRaises(ProofError):
            pa.apply("hA")

    def test_apply_unknown_hyp_rejected(self):
        pa = ProofAssistant().goal("A")
        with self.assertRaises(ProofError):
            pa.apply("nope")


class TestRewrite(unittest.TestCase):
    def test_rewrite_lr(self):
        pa = ProofAssistant().goal("(x = y) -> P x")
        pa.intro("heq")
        pa.rewrite("heq")
        self.assertEqual(pa.goals(), (parse_expr("P y"),))

    def test_rewrite_rl(self):
        pa = ProofAssistant().goal("(x = y) -> P y")
        pa.intro("heq")
        pa.rewrite("heq", "rl")
        self.assertEqual(pa.goals(), (parse_expr("P x"),))

    def test_rewrite_non_eq_rejected(self):
        pa = ProofAssistant().goal("A -> P x")
        pa.intro("hA")
        with self.assertRaises(ProofError):
            pa.rewrite("hA")

    def test_rewrite_absent_pattern_rejected(self):
        pa = ProofAssistant().goal("(x = y) -> P z")
        pa.intro("heq")
        with self.assertRaises(ProofError):
            pa.rewrite("heq")

    def test_rewrite_bad_direction_rejected(self):
        pa = ProofAssistant().goal("(x = y) -> P x")
        pa.intro("heq")
        with self.assertRaises(ProofError):
            pa.rewrite("heq", "sideways")


class TestOtherTactics(unittest.TestCase):
    def test_exact(self):
        pa = ProofAssistant().goal("A -> A").intro("h")
        pa.exact("h")
        self.assertEqual(pa.goals(), ())

    def test_exact_mismatch_rejected(self):
        pa = ProofAssistant().goal("A -> B").intro("hA")
        with self.assertRaises(ProofError):
            pa.exact("hA")

    def test_assumption(self):
        pa = ProofAssistant().goal("A -> B -> A")
        pa.intro("hA").intro("hB")
        pa.assumption()
        self.assertEqual(pa.goals(), ())

    def test_assumption_absent_rejected(self):
        pa = ProofAssistant().goal("A")
        with self.assertRaises(ProofError):
            pa.assumption()

    def test_split(self):
        pa = ProofAssistant().goal("A /\\ B")
        pa.split()
        self.assertEqual(pa.goals(), (Var("B"), Var("A")))

    def test_split_non_and_rejected(self):
        pa = ProofAssistant().goal("A")
        with self.assertRaises(ProofError):
            pa.split()

    def test_left_right(self):
        pa = ProofAssistant().goal("A \\/ B")
        pa.left()
        self.assertEqual(pa.goals(), (Var("A"),))
        pa2 = ProofAssistant().goal("A \\/ B")
        pa2.right()
        self.assertEqual(pa2.goals(), (Var("B"),))

    def test_clear(self):
        pa = ProofAssistant().goal("A -> B").intro("hA")
        pa.clear("hA")
        self.assertEqual(pa.hypotheses(), {})

    def test_clear_unknown_rejected(self):
        pa = ProofAssistant().goal("A")
        with self.assertRaises(ProofError):
            pa.clear("hA")

    def test_admit_taints(self):
        pa = ProofAssistant().goal("A")
        pa.admit()
        self.assertTrue(pa.admitted())
        cert = pa.qed(0)
        self.assertTrue(cert.admitted)


class TestQed(unittest.TestCase):
    def test_qed_certificate(self):
        pa = ProofAssistant().goal("A -> B -> A").intro("hA").intro("hB").apply("hA")
        cert = pa.qed(3)
        self.assertIsInstance(cert, ProofCertificate)
        self.assertEqual(cert.seq, 3)
        self.assertFalse(cert.admitted)
        self.assertEqual(cert.tactic_count, 4)
        self.assertTrue(cert.goal.startswith("sha256:"))
        self.assertTrue(cert.tactics_digest.startswith("sha256:"))
        d = cert.as_dict()
        self.assertEqual(d["schema"], PROOF_ASSISTANT_SCHEMA)
        self.assertEqual(d["version"], PROOF_ASSISTANT_VERSION)

    def test_qed_open_goals_rejected(self):
        pa = ProofAssistant().goal("A -> B").intro("hA")
        with self.assertRaises(ProofError):
            pa.qed(0)

    def test_qed_bad_seq_rejected(self):
        pa = ProofAssistant().goal("A").admit()
        for bad in (-1, True, "0"):
            with self.assertRaises(ProofError):
                pa.qed(bad)

    def test_qed_deterministic_digest(self):
        def run():
            pa = ProofAssistant().goal("A -> A").intro("h").apply("h")
            return pa.qed(0).tactics_digest
        self.assertEqual(run(), run())

    def test_goal_resets_session(self):
        pa = ProofAssistant().goal("A").admit()
        pa.goal("B")
        self.assertFalse(pa.admitted())
        self.assertEqual(pa.goals(), (Var("B"),))
        self.assertEqual(pa.hypotheses(), {})

    def test_tactic_log_append_only(self):
        pa = ProofAssistant().goal("A -> A").intro("h")
        log = pa.tactic_log()
        self.assertEqual([t.name for t in log], ["goal-set", "intro"])
        self.assertIsInstance(log[0], TacticRecord)
        d = log[0].as_dict()
        self.assertEqual(d["schema"], PROOF_ASSISTANT_SCHEMA)

    def test_chaining_returns_self(self):
        pa = ProofAssistant()
        self.assertIs(pa.goal("A -> A"), pa)
        self.assertIs(pa.intro("h"), pa)
        self.assertIs(pa.apply("h"), pa)


class TestAuditEvents(unittest.TestCase):
    def test_shapes(self):
        for kind in ("goal-set", "tactic", "qed", "rejected"):
            ev = proof_assistant_audit_event(kind, 0, note="n")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], PROOF_ASSISTANT_SCHEMA)
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["seq"], 0)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ProofError):
            proof_assistant_audit_event("proved", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ProofError):
            proof_assistant_audit_event("tactic", -1)
        with self.assertRaises(ProofError):
            proof_assistant_audit_event("tactic", True)

    def test_bad_field_type_rejected(self):
        with self.assertRaises(ProofError):
            proof_assistant_audit_event("tactic", 0, payload=b"bytes")
        with self.assertRaises(ProofError):
            proof_assistant_audit_event("tactic", 0, payload={"a", "set"})


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import proof_assistant as m
        m.main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
