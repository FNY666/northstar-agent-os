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

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
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


class VerifiabilityTierMutantKillers(unittest.TestCase):
    """Killers for the eight planted faults that survived the first suite.

    Each test below names the mutant site it kills and the technique that
    drives it.  The sites and their faults:

      retF@276  ``_silver_supported``: the "no pinned verifier" refusal
      retF@278  ``_silver_supported``: the "no run command" refusal
      retF@280  ``_silver_supported``: the "no reader-accessible inputs" refusal
      retF@289  ``_gold_supported``: the "not Silver-supported" refusal
      or@479    ``_normalize_category``: the "not a str" half of the guard
      or@548    ``checklist``: the "no pinned verifier" half of the Q4 guard
      eq@656    ``main``: the laundering self-check's equality assertion
      eq@664    the ``if __name__ == "__main__"`` guard on ``main``

    The first four are *masked* refusals: ``grade`` re-checks the same
    conditions before it ever calls these helpers, so a claim that trips
    them still grades the same way under the mutant.  The killers therefore
    call the helpers directly -- the private API is what the module's own
    tier ladder is built from, and it is the module under test.
    """

    # -- retF@276 / retF@278 / retF@280: _silver_supported -------------

    def test_silver_is_unsupported_without_a_pinned_verifier(self):
        """`retF@276`: the "no pinned verifier" refusal.

        Silver requires the verifier to be *pinned* (version/commit/hash).
        A claim that names no verifier is not Silver-supported, whatever
        else it carries.  Under the mutant (``return False`` ->
        ``return True``) the helper would report Silver support for a
        claim with no verifier at all.
        """
        from verifiability_tier import _silver_supported

        claim = silver_claim(verifier_ref=None)
        self.assertFalse(_silver_supported(claim))
        # The control: with the verifier pinned the same claim is supported.
        self.assertTrue(_silver_supported(silver_claim()))

    def test_silver_is_unsupported_without_a_run_command(self):
        """`retF@278`: the "no run command" refusal.

        "A reader can run it locally/offline" needs something to run.
        Without a ``run_command`` there is no runnable verifier, so the
        claim is not Silver-supported.
        """
        from verifiability_tier import _silver_supported

        claim = silver_claim(run_command=None)
        self.assertFalse(_silver_supported(claim))
        self.assertTrue(_silver_supported(silver_claim()))

    def test_silver_is_unsupported_without_reader_accessible_inputs(self):
        """`retF@280`: the "no reader-accessible inputs" refusal.

        The third Silver condition is that the reader can run the verifier
        on inputs the reader can reach.  A claim with an empty input set
        fails it.
        """
        from verifiability_tier import _silver_supported

        claim = silver_claim(inputs=())
        self.assertFalse(_silver_supported(claim))
        self.assertTrue(_silver_supported(silver_claim()))

    # -- retF@289: _gold_supported ---------------------------------------

    def test_gold_is_unsupported_when_the_claim_is_not_silver_supported(self):
        """`retF@289`: the "not Silver-supported" refusal.

        Gold (REPLICATED) sits ABOVE Silver (VERIFIED) on the ladder: a
        claim that is not Silver-supported cannot be Gold, however much
        replication and failure-mode evidence it carries.  Under the
        mutant (``return False`` -> ``return True``) a claim that is
        missing, say, the pinned verifier but names a replication and a
        fail condition would read as Gold -- Gold is supposed to be
        strictly stronger than Silver, not a side door around it.
        """
        from verifiability_tier import _gold_supported

        # Replication and explicit failure modes are present, but the
        # pinned verifier is missing: not Silver, so not Gold.
        claim = silver_claim(
            verifier_ref=None,
            replication="audited by a third party",
            fail_condition="the verifier raises",
        )
        self.assertFalse(_gold_supported(claim))

    def test_gold_is_unsupported_without_replication(self):
        """`retF@291`: the "no replication" refusal.

        Gold needs independent replication / third-party audit / multiple
        implementations agreeing.  A Silver-shaped claim with no
        replication field is not Gold-supported.  Under the mutant
        (``return False`` -> ``return True``) every Silver claim would
        read as Gold, so the whole tier ladder would collapse.
        """
        from verifiability_tier import _gold_supported

        claim = silver_claim()  # Silver-shaped, no replication
        self.assertFalse(_gold_supported(claim))
        # The control: with replication and explicit failure modes it is.
        self.assertTrue(
            _gold_supported(silver_claim(replication="audited by a third party"))
        )

    def test_gold_is_unsupported_without_explicit_failure_modes(self):
        """`retF@289`: the neighbouring refusal, as a control.

        "failure modes and assumptions are explicit": replication alone,
        with the failure modes left implicit, is still not Gold.  This
        pins the other half of the Gold guard so the replication refusal
        above is not the only thing separating it from Gold.
        """
        from verifiability_tier import _gold_supported

        claim = silver_claim(
            replication="audited by a third party",
            fail_condition=None,
            assumptions=(),
        )
        self.assertFalse(_gold_supported(claim))

    # -- or@479: _normalize_category -------------------------------------

    def test_a_non_string_claimed_category_is_refused(self):
        """`or@479`: the "not a str" half of the guard.

        The guard is ``not isinstance(value, str) or not value.strip()``.
        The "not a str" half is the only thing that refuses a non-string
        category; the "strips empty" half never sees one.  Under the
        mutant (``or`` -> ``and``) a non-string category falls through to
        ``value.strip()`` and dies with an ``AttributeError`` instead of
        the module's own ``InvalidClaimError``.
        """
        from verifiability_tier import _normalize_category

        with self.assertRaises(InvalidClaimError):
            _normalize_category(123, "claimed_category")
        with self.assertRaises(InvalidClaimError):
            _normalize_category(None, "claimed_category")
        with self.assertRaises(InvalidClaimError):
            _normalize_category(["execution"], "claimed_category")

    def test_a_blank_string_claimed_category_is_refused(self):
        """`or@479`: the other half, as the control.

        A string that strips to empty is refused too.  This is the arm
        the mutant leaves intact, so it is pinned here to show the two
        halves refuse different things.
        """
        from verifiability_tier import _normalize_category

        with self.assertRaises(InvalidClaimError):
            _normalize_category("   ", "claimed_category")
        self.assertEqual(_normalize_category("execution", "claimed_category"), "execution")

    # -- or@548: checklist's Q4 guard ------------------------------------

    def test_q4_is_unanswered_when_the_verifier_is_pinned_but_no_scope(self):
        """`or@548`: the "no pinned verifier" half of the Q4 guard.

        The guard is ``not claim.has_verifier or not
        claim.scope_not_claimed``: Q4 ("what is pinned, and what can
        change silently") needs BOTH a pinned verifier and an explicit
        ``scope_not_claimed``.  A claim that pins the verifier but names
        no scope has NOT answered Q4 -- the second arm is the only one
        that fires.  Under the mutant (``or`` -> ``and``) the first arm is
        False, the whole guard is False, and Q4 would be silently dropped
        from the checklist.
        """
        claim = Claim(
            statement="the tool wrote the file",
            verifier_ref="git:abc1234",
        )
        unanswered = checklist(claim)
        self.assertIn("Q4", unanswered)
        # Q3 is answered (the verifier is pinned); Q4 is not.
        self.assertNotIn("Q3", unanswered)
        self.assertEqual(checklist_report(claim)["Q4"], "unanswered")

    def test_q4_is_unanswered_when_there_is_no_verifier_even_with_a_scope(self):
        """`or@548`: the other half, as the control.

        A claim that names no verifier cannot say what is pinned, so Q4
        is unanswered even when it does name a scope.  This is the arm
        the mutant leaves intact; pinning it keeps the two halves
        distinguished.
        """
        claim = Claim(
            statement="the tool wrote the file",
            scope_not_claimed=("does not claim the events were correct",),
        )
        unanswered = checklist(claim)
        self.assertIn("Q4", unanswered)
        self.assertIn("Q3", unanswered)

    # -- eq@656: main()'s laundering self-check --------------------------

    def test_main_self_check_passes(self):
        """`eq@656`: the equality assertion inside ``main``.

        ``main`` is the module's self-check; its worked example asserts
        that a proof of execution presented as a proof of safety is
        detected, with the exact source's wording.  Under the mutant
        (``==`` -> ``!=``) that assertion is inverted and the self-check
        raises instead of reporting "ok".
        """
        import verifiability_tier

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            verifiability_tier.main()
        self.assertIn("ok", buffer.getvalue())

    def test_main_self_check_runs_clean_as_a_script(self):
        """`eq@656`: the same self-check, run the way a reader would.

        Running the module as a script must print the self-check line and
        exit zero.  Under the mutant the inverted assertion makes the
        script die with a non-zero status and no output.
        """
        module_path = Path(verifiability_tier_path())
        result = subprocess.run(
            [sys.executable, str(module_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verifiability-tier self-check: ok", result.stdout)

    # -- eq@664: the __main__ guard --------------------------------------

    def test_importing_the_module_does_not_run_the_self_check(self):
        """`eq@664`: the ``if __name__ == "__main__"`` guard.

        Importing a module must not run its self-check: the guard is
        what keeps ``main()`` off the import path.  Under the mutant
        (``==`` -> ``!=``) importing the module executes ``main()`` and
        prints the self-check line from a plain import.
        """
        module_path = Path(verifiability_tier_path())
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, %r); import verifiability_tier"
                % str(module_path.parent),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")


def verifiability_tier_path():
    """Absolute path to the module under test."""
    return Path(__file__).resolve().parents[1] / "verifiability_tier.py"


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
