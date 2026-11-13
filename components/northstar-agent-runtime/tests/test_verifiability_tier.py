"""Tests for verifiability_tier.py.

Verifiability tiers grade how *checkable* a claim is -- Bronze/Silver/Gold --
and detect proof laundering, the practice of proving one thing and presenting
the proof as another.  The rules come from pleroma, "Proof is not a vibe: an
anti-verifiability-theater checklist for agents" (Moltbook post 238cb8a3,
2026-03-02).

These tests drive the whole path, not just the parts: they show that a
Silver-shaped claim grades VERIFIED, that a self-described Gold claim is
downgraded to what its fields support, that the Q1-Q3 cap holds, and that a
proof of execution presented as a proof of safety is caught.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verifiability_tier import (  # noqa: E402
    SCHEMA_PIN,
    VERSION,
    Claim,
    InvalidClaimError,
    Tier,
    asserted_tier,
    checklist,
    checklist_report,
    detect_proof_laundering,
    downgrade_notice,
    grade,
    grade_with_reason,
    proof_category,
)


def silver_claim(**overrides):
    """A complete Silver claim: pinned verifier, runnable offline, output format."""
    fields = dict(
        statement="the ledger chain verifies against the genesis key",
        verifier_ref="git:abc1234",
        inputs=("ledger.jsonl",),
        run_command="python3 -m northstar verify ledger.jsonl",
        expected_output="verify: ok",
        fail_condition="the verifier raises",
        assumptions=("the reader holds the genesis key",),
        scope_not_claimed=("does not claim the recorded events were correct",),
        who_controls_inputs="the repository",
        threat_model="proof of execution",
    )
    fields.update(overrides)
    return Claim(**fields)


class VerifiabilityTierTests(unittest.TestCase):
    # -- the source's three-part test -------------------------------------

    def test_silver_claim_grades_verified(self):
        # A complete Silver claim: statement + pinned verifier + a reader
        # can run it offline on reader-accessible inputs + output format
        # specified.  All three Silver conditions are present.
        claim = silver_claim()
        self.assertIs(grade(claim), Tier.VERIFIED)
        self.assertEqual(grade_with_reason(claim)["tier"], "VERIFIED")

    def test_statement_only_claim_grades_claimed(self):
        # A statement with nothing else: the source's CLAIMED label --
        # "statement exists, but the verifier is not runnable or pinned".
        claim = Claim(statement="the tool wrote the file")
        self.assertIs(grade(claim), Tier.CLAIMED)

    def test_missing_statement_grades_untested(self):
        # No statement: nothing is being proven.  Fail closed.
        claim = Claim(
            verifier_ref="git:abc1234",
            inputs=("ledger.jsonl",),
            run_command="python3 -m northstar verify ledger.jsonl",
            expected_output="verify: ok",
        )
        self.assertIs(grade(claim), Tier.UNTESTED)
        self.assertIn("Q1", checklist(claim))

    def test_q1_q3_unanswered_caps_at_untested_even_when_other_fields_present(self):
        # The source: "If Q1-Q3 are unanswered, label it UNTESTED".  Here the
        # claim poses as a proof (pinned verifier + run command) but never
        # names reader-accessible inputs, so Q2 is unanswered and the cap
        # holds even though every other field is filled in.
        claim = silver_claim(inputs=())
        self.assertIs(grade(claim), Tier.UNTESTED)
        self.assertIn("Q2", checklist(claim))

    def test_claim_without_inputs_or_verifier_is_untested_when_it_poses_as_proof(self):
        # A claim that names a replication but neither inputs nor a
        # verifier: Q1-Q3 unanswered -> UNTESTED.
        claim = Claim(
            statement="the tool wrote the file",
            replication="two independent auditors reproduced this",
        )
        self.assertIs(grade(claim), Tier.UNTESTED)

    # -- the author's self-description never raises the grade --------------

    def test_self_asserted_gold_is_downgraded_to_supported_tier(self):
        # The claim calls itself Gold but carries no replication evidence:
        # it lands on VERIFIED, the tier its fields support.
        claim = silver_claim(asserted_tier="Gold")
        self.assertIs(grade(claim), Tier.VERIFIED)
        self.assertIs(asserted_tier(claim), Tier.REPLICATED)
        notice = downgrade_notice(claim)
        self.assertIsNotNone(notice)
        self.assertIn("REPLICATED", notice)
        self.assertIn("VERIFIED", notice)

    def test_self_asserted_gold_without_replication_never_reaches_gold(self):
        # The exact downgrade path: a self-described Gold claim whose only
        # missing piece is the replication evidence grades VERIFIED.
        claim = silver_claim(asserted_tier="GOLD")
        self.assertIs(grade(claim), Tier.VERIFIED)
        self.assertNotEqual(grade(claim), Tier.REPLICATED)

    def test_grade_uses_fields_not_the_asserted_tier(self):
        # Two claims with identical fields but different self-descriptions
        # grade identically.  The label is not an input.
        quiet = silver_claim()
        loud = silver_claim(asserted_tier="REPLICATED")
        self.assertIs(grade(quiet), grade(loud))
        self.assertIs(downgrade_notice(quiet), None)

    # -- the ten questions -------------------------------------------------

    def test_checklist_reports_unanswered_questions(self):
        claim = Claim(statement="the tool wrote the file")
        unanswered = checklist(claim)
        self.assertIn("Q2", unanswered)
        self.assertIn("Q3", unanswered)
        self.assertNotIn("Q1", unanswered)
        report = checklist_report(claim)
        self.assertEqual(report["Q1"], "answered")
        self.assertEqual(report["Q3"], "unanswered")

    def test_full_claim_answers_every_question(self):
        claim = silver_claim(replication="audited by a third party")
        self.assertEqual(checklist(claim), [])
        report = checklist_report(claim)
        self.assertTrue(all(v == "answered" for v in report.values()))

    # -- proof laundering --------------------------------------------------

    def test_execution_proof_presented_as_safety_proof_is_detected(self):
        # The source's first named variant.  The claim proves that the
        # tool ran; the reader is invited to believe it proves safety.
        claim = silver_claim(
            statement="the agent executed the tool",
            threat_model="proof of execution",
        )
        finding = detect_proof_laundering(claim, "safety")
        self.assertIsNotNone(finding)
        self.assertEqual(
            finding, "proof of execution presented as proof of safety"
        )

    def test_proxy_metric_proof_presented_as_objective_is_detected(self):
        # The source's third named variant: a proxy metric proof dressed up
        # as a proof about the real objective.
        claim = silver_claim(
            statement="the proxy metric improved",
            threat_model="proof about a proxy metric",
        )
        finding = detect_proof_laundering(claim, "objective")
        self.assertIsNotNone(finding)
        self.assertIn("proxy metric", finding)
        self.assertIn("real objective", finding)

    def test_matching_categories_do_not_alarm(self):
        claim = silver_claim(threat_model="proof of execution")
        self.assertIsNone(detect_proof_laundering(claim, "execution"))
        self.assertEqual(proof_category(claim), "execution")

    def test_correctness_proof_presented_as_safety_proof_is_detected(self):
        # The source's second named variant.
        claim = silver_claim(
            statement="the transformation is equivalent to the reference",
            threat_model="proof of correctness",
        )
        finding = detect_proof_laundering(claim, "safety")
        self.assertIsNotNone(finding)
        self.assertEqual(
            finding, "proof of correctness presented as proof of safety"
        )

    def test_claim_that_does_not_say_what_kind_of_proof_it_is_does_not_alarm(self):
        # No category to compare against: not a laundering finding.  It is a
        # checklist failure (Q8), which the checklist reports.
        claim = silver_claim(threat_model=None)
        self.assertIsNone(detect_proof_laundering(claim, "safety"))
        self.assertIn("Q8", checklist(claim))

    # -- Bronze ------------------------------------------------------------

    def test_bronze_claim_grades_checkable(self):
        # Bronze: statement explicit, verification steps described, not run.
        claim = Claim(
            statement="the transformation is equivalent to the reference",
            verifier_ref="git:abc1234",
            inputs=("reference.jsonl",),
            run_command="python3 -m northstar diff reference.jsonl",
        )
        self.assertIs(grade(claim), Tier.CHECKABLE)

    def test_silver_requires_all_three_conditions(self):
        # Each Silver condition is load-bearing: drop the pinned verifier,
        # the run command, the inputs, or the output format, and the claim
        # is no longer VERIFIED.
        self.assertLessEqual(
            grade(silver_claim(verifier_ref=None)).strength, Tier.CLAIMED.strength
        )
        self.assertIs(grade(silver_claim(run_command=None)), Tier.CLAIMED)
        self.assertIs(grade(silver_claim(expected_output=None)), Tier.CHECKABLE)
        self.assertIs(grade(silver_claim(inputs=())), Tier.UNTESTED)

    def test_gold_requires_replication_and_explicit_failure_modes(self):
        # Replication alone, with the failure modes left implicit, is not
        # Gold.
        no_modes = silver_claim(
            replication="audited by a third party",
            fail_condition=None,
            assumptions=(),
        )
        self.assertIs(grade(no_modes), Tier.VERIFIED)
        with_modes = silver_claim(
            replication="audited by a third party",
            fail_condition="the verifier raises",
            assumptions=(),
        )
        self.assertIs(grade(with_modes), Tier.REPLICATED)

    def test_no_verifier_ref_never_reaches_verified(self):
        # "no verifier_ref -> at most CLAIMED": a claim that names a run
        # command and inputs but pins nothing is not runnable.  It poses as
        # a proof with Q3 unanswered, so the source's cap puts it at
        # UNTESTED -- which is at most CLAIMED in strength, and never
        # VERIFIED.
        claim = silver_claim(verifier_ref=None)
        graded = grade(claim)
        self.assertNotEqual(graded, Tier.VERIFIED)
        self.assertLessEqual(graded.strength, Tier.CLAIMED.strength)
        self.assertIn("Q3", checklist(claim))

    # -- fail closed -------------------------------------------------------

    def test_empty_claim_is_untested(self):
        self.assertIs(grade(Claim()), Tier.UNTESTED)

    def test_grade_rejects_non_claim(self):
        with self.assertRaises(InvalidClaimError):
            grade({"statement": "not a claim"})

    def test_claim_rejects_non_string_inputs(self):
        with self.assertRaises(InvalidClaimError):
            Claim(statement="x", inputs="ledger.jsonl")

    def test_module_pins_are_present(self):
        self.assertEqual(VERSION, "verifiability-tier.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.verifiability-tier.v1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
