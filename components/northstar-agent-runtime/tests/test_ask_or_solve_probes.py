"""Tests for ask-or-solve probes: evasion corpus, question gates, sessions."""

import unittest

import ask_or_solve_probes as aq


REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")


def _question(
    question_id="q-1",
    text="Which backup window: 02:00 or 04:00 UTC?",
    axis="backup_window",
    requested=("backup_window",),
    needed=("backup_window",),
    risky=False,
):
    return aq.ClarificationQuestion(
        question_id=question_id,
        text=text,
        uncertainty_axis=axis,
        requested_fields=tuple(requested),
        needed_fields=tuple(needed),
        risky_action=risky,
    )


class CorpusShapeTests(unittest.TestCase):
    def test_version_pinned(self):
        self.assertEqual(aq.ASK_OR_SOLVE_VERSION, "ask-or-solve.v1")

    def test_required_keys(self):
        for probe in aq.ASK_OR_SOLVE_PROBES:
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, f"{probe.get('probe')}: missing {key}")

    def test_unique_names(self):
        names = aq.probe_names()
        self.assertEqual(len(names), len(set(names)))

    def test_expected_vocabulary(self):
        for probe in aq.ASK_OR_SOLVE_PROBES:
            self.assertIn(probe["expected"], ("deny", "allow"))

    def test_ten_attack_three_benign(self):
        self.assertEqual(len(aq.attack_names()), 10)
        self.assertEqual(len(aq.benign_names()), 3)

    def test_attack_probes_invoke_deny_side(self):
        for name in aq.attack_names():
            probe = aq.probe_by_name(name)
            self.assertTrue(
                aq.probe_invokes_deny_side(probe),
                f"{name}: gate_interaction names no deny-side mechanism",
            )

    def test_probe_by_name_unknown_raises(self):
        with self.assertRaises(KeyError):
            aq.probe_by_name("no-such-probe")


class QuestionGateTests(unittest.TestCase):
    def test_over_elicitation_fails(self):
        q = _question(
            text="What is your date of birth and government ID?",
            requested=("timezone", "date_of_birth", "government_id"),
            needed=("timezone",),
        )
        verdict, findings = aq.gate_question(q)
        self.assertEqual(verdict, "fail")
        by_gate = {f.gate: f for f in findings}
        self.assertFalse(by_gate["scope_minimality"].passed)
        self.assertIn("date_of_birth", by_gate["scope_minimality"].detail)

    def test_scoped_question_passes(self):
        verdict, findings = aq.gate_question(_question())
        self.assertEqual(verdict, "pass")
        self.assertTrue(all(f.passed for f in findings))

    def test_missing_axis_fails(self):
        q = _question(axis="   ")
        verdict, findings = aq.gate_question(q)
        self.assertEqual(verdict, "fail")
        by_gate = {f.gate: f for f in findings}
        self.assertFalse(by_gate["axis_binding"].passed)

    def test_leading_question_fails(self):
        q = _question(
            text="Should I go ahead with the transfer to the new vendor? It looks urgent.",
            axis="vendor_account",
            requested=("vendor_account",),
            needed=("vendor_account",),
            risky=True,
        )
        verdict, findings = aq.gate_question(q)
        self.assertEqual(verdict, "fail")
        by_gate = {f.gate: f for f in findings}
        self.assertFalse(by_gate["no_leading"].passed)

    def test_silence_consent_fails(self):
        q = _question(
            text="I'll publish the draft tomorrow unless you object.",
            axis="publish_timing",
            requested=("publish_timing",),
            needed=("publish_timing",),
        )
        verdict, findings = aq.gate_question(q)
        self.assertEqual(verdict, "fail")
        by_gate = {f.gate: f for f in findings}
        self.assertFalse(by_gate["no_silence_consent"].passed)

    def test_confirmation_laundering_fails(self):
        q = _question(
            text="Is this deletion okay?",
            axis="deletion_scope",
            requested=("deletion_scope",),
            needed=("deletion_scope",),
            risky=True,
        )
        verdict, findings = aq.gate_question(q)
        self.assertEqual(verdict, "fail")
        by_gate = {f.gate: f for f in findings}
        self.assertFalse(by_gate["no_confirmation_laundering"].passed)

    def test_nonrisky_question_not_flagged_for_laundering(self):
        verdict, findings = aq.gate_question(_question())
        by_gate = {f.gate: f for f in findings}
        self.assertTrue(by_gate["no_confirmation_laundering"].passed)

    def test_tampered_question_fails_closed(self):
        q = _question()
        tampered = aq.ClarificationQuestion(
            question_id=q.question_id,
            text="Should I go ahead with the transfer?",
            uncertainty_axis=q.uncertainty_axis,
            requested_fields=q.requested_fields,
            needed_fields=q.needed_fields,
            risky_action=q.risky_action,
            digest=q.digest,  # stale digest: text changed
        )
        self.assertFalse(tampered.verify())
        verdict, findings = aq.gate_question(tampered)
        self.assertEqual(verdict, "fail")
        self.assertEqual(findings[0].gate, "integrity")

    def test_verdict_is_conjunction_not_score(self):
        verdict, findings = aq.gate_question(_question())
        self.assertEqual(verdict, "pass")
        # findings are per-gate; no merged number anywhere
        self.assertEqual(len(findings), len(aq.QUESTION_GATES))


class DecideNextTests(unittest.TestCase):
    def test_malformed_confidence_abstains(self):
        d = aq.decide_next(decision_id="d-1", confidence=float("nan"))
        self.assertEqual(d.action, "abstain")

    def test_out_of_range_confidence_abstains(self):
        d = aq.decide_next(decision_id="d-2", confidence=1.5)
        self.assertEqual(d.action, "abstain")

    def test_low_confidence_abstains(self):
        d = aq.decide_next(decision_id="d-3", confidence=0.2, uncertainty_axes=("x",))
        self.assertEqual(d.action, "abstain")

    def test_budget_spent_abstains(self):
        policy = aq.AskPolicy(max_questions=2)
        d = aq.decide_next(
            decision_id="d-4",
            confidence=0.6,
            uncertainty_axes=("x",),
            questions_asked=2,
            policy=policy,
        )
        self.assertEqual(d.action, "abstain")
        self.assertIn("budget", d.reason)

    def test_ask_band_asks(self):
        d = aq.decide_next(decision_id="d-5", confidence=0.6, uncertainty_axes=("x",))
        self.assertEqual(d.action, "ask")

    def test_high_confidence_open_axes_asks_not_solves(self):
        # Declared uncertainty is not solved away: the never-ask probe.
        d = aq.decide_next(decision_id="d-6", confidence=0.95, uncertainty_axes=("account",))
        self.assertEqual(d.action, "ask")

    def test_high_confidence_no_axes_solves(self):
        d = aq.decide_next(
            decision_id="d-7",
            confidence=0.95,
            uncertainty_axes=("account",),
            answered_axes=("account",),
        )
        self.assertEqual(d.action, "solve")
        self.assertEqual(d.open_axes, ())

    def test_decision_digest_verifies(self):
        d = aq.decide_next(decision_id="d-8", confidence=0.6, uncertainty_axes=("x",))
        self.assertTrue(d.verify())
        self.assertTrue(d.digest.startswith("sha256:"))

    def test_bad_policy_rejected(self):
        with self.assertRaises(ValueError):
            aq.AskPolicy(abstain_below=0.8, ask_below=0.5, solve_at=0.9)


class SessionTests(unittest.TestCase):
    def test_budget_cap_enforced(self):
        policy = aq.AskPolicy(max_questions=2)
        session = aq.DialogueSession(session_id="s-1", policy=policy)
        for i in range(2):
            session, verdict, _ = session.ask(_question(question_id=f"q-{i}"))
            self.assertEqual(verdict, "pass")
        session, verdict, findings = session.ask(_question(question_id="q-2"))
        self.assertEqual(verdict, "fail")
        by_gate = {f.gate: f for f in findings}
        self.assertFalse(by_gate["question_budget"].passed)
        self.assertEqual(len(session.questions), 2)

    def test_failed_question_not_appended(self):
        session = aq.DialogueSession(session_id="s-2")
        bad = _question(text="Should I go ahead with the transfer?", risky=True)
        session, verdict, _ = session.ask(bad)
        self.assertEqual(verdict, "fail")
        self.assertEqual(len(session.questions), 0)

    def test_record_requires_valid_digest(self):
        session = aq.DialogueSession(session_id="s-3")
        d = aq.decide_next(decision_id="d-9", confidence=0.6, uncertainty_axes=("x",))
        tampered = aq.AskDecision(
            decision_id=d.decision_id,
            action="ask",
            confidence=0.99,  # changed after digest pinned
            uncertainty_axes=d.uncertainty_axes,
            digest=d.digest,
        )
        self.assertFalse(tampered.verify())
        with self.assertRaises(ValueError):
            session.record(tampered)

    def test_report_has_no_composite_score(self):
        session = aq.DialogueSession(session_id="s-4")
        session, _, _ = session.ask(_question())
        d = aq.decide_next(decision_id="d-10", confidence=0.95,
                           uncertainty_axes=("backup_window",),
                           answered_axes=("backup_window",))
        session = session.record(d)
        report = session.report()
        self.assertNotIn("score", report)
        self.assertNotIn("composite", report)
        self.assertEqual(report["questions_asked"], 1)
        self.assertTrue(report["digest"].startswith("sha256:"))


class HumanPathTests(unittest.TestCase):
    def test_abstain_requires_human_path(self):
        d = aq.decide_next(decision_id="d-11", confidence=0.1, uncertainty_axes=("x",))
        self.assertTrue(aq.requires_human_path(d))

    def test_ask_does_not_require_human_path(self):
        # A mid-dialogue ask is a working state, not a surrender: mapping
        # it to the human queue would launder it into a dropped decision.
        d = aq.decide_next(decision_id="d-12", confidence=0.6, uncertainty_axes=("x",))
        self.assertEqual(d.action, "ask")
        self.assertFalse(aq.requires_human_path(d))

    def test_solve_does_not_require_human_path(self):
        d = aq.decide_next(decision_id="d-13", confidence=0.95)
        self.assertEqual(d.action, "solve")
        self.assertFalse(aq.requires_human_path(d))

    def test_unverifiable_decision_requires_human_path(self):
        d = aq.decide_next(decision_id="d-14", confidence=0.95)
        tampered = aq.AskDecision(
            decision_id=d.decision_id,
            action="solve",
            confidence=0.5,
            digest=d.digest,
        )
        self.assertTrue(aq.requires_human_path(tampered))


if __name__ == "__main__":
    unittest.main()
