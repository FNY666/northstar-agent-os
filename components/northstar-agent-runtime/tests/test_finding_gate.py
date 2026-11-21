"""The finding gate: seven questions before a finding ships.

These tests pin the gate's behaviour, not its text.  The properties that
matter are:

* every fixture yields its own verdict -- a true finding passes, a
  status-code-only bypass is killed, a non-reproducible finding is killed,
  a finding that needs a second step is routed to the chain builder, a
  real-but-low-impact finding is downgraded, a never-submit finding is
  killed, a finding that needs unattainable privilege is killed, and an
  already-known behaviour is killed;
* the **pre-gate** (can the attacker act now / what does the victim lose /
  is it reproducible in ten minutes) is asked *first*: a finding that
  fails any of them is killed before the seven questions run;
* the **layer-ordering trap** is enforced: an error response or a status
  code is not a proof that authentication was passed, and a bypass claim
  without a minimal well-formed-body re-send is killed;
* the gate is **pure**: the same finding yields the same verdict on every
  run, and nothing outside the argument is read;
* the wiring holds a killed finding through the refusal-hold seam and
  lets the run continue.

The methodology is adapted from Claude-BugHunter's triage-validation
gate (https://github.com/elementalsouls/Claude-BugHunter.git); the
questions here are Northstar's own wording.  See
``docs/design/bughunter-finding-gate.md``.
"""

from __future__ import annotations

import unittest

import finding_gate
from finding_gate import (
    ACCEPTED_IMPACT_KINDS,
    PROOF_CONCRETE,
    PROOF_ERROR_RESPONSE,
    PROOF_NONE,
    PROOF_STATUS_CODE,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    VERDICT_CHAIN_REQUIRED,
    VERDICT_DOWNGRADE,
    VERDICT_KILL,
    VERDICT_PASS,
    Finding,
    FindingGateError,
    apply_finding_gate,
    evaluate_finding,
)


def true_finding(**overrides) -> Finding:
    """A finding that passes every question."""
    base = dict(
        attacker_steps=("POST /api/import {\"rows\": 1}",),
        impact="the attacker reads another tenant's rows",
        impact_kind="data-exposure",
        in_scope_asset="app/api/import.py",
        required_privilege="none",
        known_behavior=False,
        impact_proof="the response body carried another tenant's row id 42",
        impact_proof_kind=PROOF_CONCRETE,
        minimal_body_resent=False,
        never_submit=False,
        attacker_can_act_now=True,
        repro_minutes=10,
        severity=SEVERITY_HIGH,
        chain_required=False,
        claims_auth_bypass=False,
        low_impact=False,
    )
    base.update(overrides)
    return Finding(**base)


class TrueFindingTests(unittest.TestCase):
    """A finding that is real passes the gate."""

    def test_a_true_finding_passes(self):
        verdict = evaluate_finding(true_finding())
        self.assertEqual(verdict.outcome, VERDICT_PASS)
        self.assertTrue(verdict.shipped)
        self.assertFalse(verdict.killed)

    def test_a_true_finding_keeps_its_severity(self):
        verdict = evaluate_finding(true_finding(severity=SEVERITY_HIGH))
        self.assertEqual(verdict.severity, SEVERITY_HIGH)

    def test_the_passing_reason_names_the_whole_run(self):
        verdict = evaluate_finding(true_finding())
        self.assertEqual(verdict.question, "final")
        self.assertIn("seven questions", verdict.reason)


class LayerOrderingTrapTests(unittest.TestCase):
    """An error response or a status code is not a proof of a bypass."""

    def test_a_status_code_only_bypass_is_killed(self):
        verdict = evaluate_finding(
            true_finding(
                impact_proof="a 200 instead of the expected 403",
                impact_proof_kind=PROOF_STATUS_CODE,
                claims_auth_bypass=True,
            )
        )
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[5])

    def test_an_error_response_only_bypass_is_killed(self):
        verdict = evaluate_finding(
            true_finding(
                impact_proof="the endpoint answered 500",
                impact_proof_kind=PROOF_ERROR_RESPONSE,
                claims_auth_bypass=True,
            )
        )
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("layer-ordering trap", verdict.reason)

    def test_a_bypass_claim_without_a_minimal_body_resend_is_killed(self):
        verdict = evaluate_finding(
            true_finding(
                impact_proof="the request reached the handler as an admin",
                impact_proof_kind=PROOF_CONCRETE,
                claims_auth_bypass=True,
                minimal_body_resent=False,
            )
        )
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("minimal", verdict.reason)

    def test_a_bypass_claim_with_a_minimal_body_resend_passes(self):
        verdict = evaluate_finding(
            true_finding(
                impact_proof="the request reached the handler as an admin",
                impact_proof_kind=PROOF_CONCRETE,
                claims_auth_bypass=True,
                minimal_body_resent=True,
            )
        )
        self.assertEqual(verdict.outcome, VERDICT_PASS)

    def test_a_finding_with_no_proof_at_all_is_killed(self):
        verdict = evaluate_finding(
            true_finding(impact_proof="", impact_proof_kind=PROOF_NONE)
        )
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("technically possible", verdict.reason)


class GateZeroTests(unittest.TestCase):
    """The pre-gate runs first, and each of its three questions is fatal."""

    def test_a_non_reproducible_finding_is_killed(self):
        verdict = evaluate_finding(true_finding(repro_minutes=45))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.GATE_0_QUESTIONS[2])
        self.assertIn("ten minutes", verdict.reason)

    def test_a_finding_with_unknown_repro_time_is_killed(self):
        verdict = evaluate_finding(true_finding(repro_minutes=None))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.GATE_0_QUESTIONS[2])

    def test_a_finding_the_attacker_cannot_act_on_is_killed(self):
        verdict = evaluate_finding(true_finding(attacker_can_act_now=False))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.GATE_0_QUESTIONS[0])

    def test_a_finding_where_the_victim_loses_nothing_is_killed(self):
        verdict = evaluate_finding(true_finding(impact=""))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.GATE_0_QUESTIONS[1])

    def test_the_pre_gate_runs_before_the_seven_questions(self):
        # The finding is otherwise perfect, but it fails the pre-gate, so
        # the question that killed it must be a pre-gate question and not
        # any of the seven.
        verdict = evaluate_finding(true_finding(repro_minutes=600))
        self.assertNotIn(verdict.question, finding_gate.QUESTIONS)
        self.assertTrue(verdict.question.startswith("gate-0"))

    def test_a_reproducible_finding_in_ten_minutes_passes_the_pre_gate(self):
        verdict = evaluate_finding(true_finding(repro_minutes=10))
        self.assertEqual(verdict.outcome, VERDICT_PASS)


class VerdictFixtureTests(unittest.TestCase):
    """Each of the eight fixtures yields its own verdict."""

    def test_a_finding_that_needs_a_second_step_is_chain_required(self):
        verdict = evaluate_finding(true_finding(chain_required=True))
        self.assertEqual(verdict.outcome, VERDICT_CHAIN_REQUIRED)
        self.assertIn("chain builder", verdict.reason)

    def test_a_real_but_low_impact_finding_is_downgraded(self):
        verdict = evaluate_finding(true_finding(low_impact=True, severity=SEVERITY_MEDIUM))
        self.assertEqual(verdict.outcome, VERDICT_DOWNGRADE)
        self.assertEqual(verdict.severity, SEVERITY_LOW)

    def test_a_finding_on_the_never_submit_list_is_killed(self):
        verdict = evaluate_finding(true_finding(never_submit=True))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[6])
        self.assertIn("never-submit", verdict.reason)

    def test_a_finding_needing_unattainable_privilege_is_killed(self):
        verdict = evaluate_finding(true_finding(required_privilege="cluster-admin"))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[3])
        self.assertIn("cannot get", verdict.reason)

    def test_an_already_known_behaviour_is_killed(self):
        verdict = evaluate_finding(true_finding(known_behavior=True))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[4])
        self.assertIn("already known", verdict.reason)

    def test_a_finding_whose_impact_is_not_accepted_is_killed(self):
        verdict = evaluate_finding(true_finding(impact_kind="ui-nit"))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[1])

    def test_a_finding_with_no_attacker_steps_is_killed(self):
        verdict = evaluate_finding(true_finding(attacker_steps=()))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[0])

    def test_attacker_steps_that_are_not_real_requests_are_killed(self):
        verdict = evaluate_finding(true_finding(attacker_steps=("log in as the admin",)))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[0])
        self.assertIn("real requests", verdict.reason)

    def test_a_finding_with_no_in_scope_asset_is_killed(self):
        verdict = evaluate_finding(true_finding(in_scope_asset=""))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertEqual(verdict.question, finding_gate.QUESTIONS[2])


class PurityTests(unittest.TestCase):
    """The gate is a pure function of its argument."""

    def test_the_same_finding_yields_the_same_verdict_every_time(self):
        finding = true_finding()
        first = evaluate_finding(finding)
        for _ in range(5):
            self.assertEqual(evaluate_finding(finding), first)

    def test_the_verdict_is_identical_across_two_equal_findings(self):
        self.assertEqual(evaluate_finding(true_finding()), evaluate_finding(true_finding()))

    def test_the_gate_reads_no_clock_and_no_randomness(self):
        # The module must not import anything that could make the verdict
        # depend on the wall clock, the network, the filesystem or a
        # random draw: a verdict that moved between two runs would make
        # the mutant probe and the bench meaningless.
        source = open(finding_gate.__file__, "r", encoding="utf-8").read()
        for forbidden in ("import time", "import random", "import socket", "import datetime"):
            self.assertNotIn(forbidden, source)

    def test_the_gate_does_not_mutate_the_finding(self):
        finding = true_finding()
        before = finding.as_dict()
        evaluate_finding(finding)
        self.assertEqual(finding.as_dict(), before)

    def test_a_mapping_finding_is_accepted_and_gives_the_same_verdict(self):
        payload = true_finding().as_dict()
        self.assertEqual(evaluate_finding(payload), evaluate_finding(true_finding()))

    def test_an_unknown_field_in_a_mapping_is_refused(self):
        payload = true_finding().as_dict()
        payload["severity_hint"] = "low"
        with self.assertRaises(FindingGateError):
            evaluate_finding(payload)

    def test_a_non_finding_is_refused(self):
        with self.assertRaises(FindingGateError):
            evaluate_finding("not a finding")


class WiringTests(unittest.TestCase):
    """The seam: a killed finding is held, and the run continues."""

    def test_a_killed_finding_is_held_and_not_shipped(self):
        decision = apply_finding_gate(true_finding(repro_minutes=600))
        self.assertEqual(decision.action, "hold")
        self.assertTrue(decision.held)
        self.assertFalse(decision.shipped)

    def test_a_passed_finding_is_shipped(self):
        decision = apply_finding_gate(true_finding())
        self.assertEqual(decision.action, "ship")
        self.assertTrue(decision.shipped)

    def test_a_chain_required_finding_is_routed_to_the_chain_builder(self):
        decision = apply_finding_gate(true_finding(chain_required=True))
        self.assertEqual(decision.action, "chain")
        self.assertTrue(decision.needs_chain)
        self.assertFalse(decision.held)

    def test_a_downgraded_finding_ships_at_the_lowered_severity(self):
        decision = apply_finding_gate(true_finding(low_impact=True, severity=SEVERITY_MEDIUM))
        self.assertEqual(decision.action, "downgrade")
        self.assertTrue(decision.shipped)
        self.assertEqual(decision.verdict.severity, SEVERITY_LOW)

    def test_a_held_finding_is_recorded_through_the_refusal_hold_seam(self):
        from refusal_hold_wiring import RefusalHoldRegistry

        registry = RefusalHoldRegistry()
        decision = apply_finding_gate(
            true_finding(repro_minutes=600),
            registry=registry,
            grant_id="g-1",
            action="ship_finding",
            subject="f-1",
        )
        self.assertTrue(decision.held)
        result = registry.check("g-1", "ship_finding", "f-1")
        self.assertTrue(result.blocked)

    def test_the_run_continues_after_a_finding_is_held(self):
        # The gate kills a *finding*, never the run: the next finding is
        # gated independently and a good one still ships.
        from refusal_hold_wiring import RefusalHoldRegistry

        registry = RefusalHoldRegistry()
        apply_finding_gate(
            true_finding(repro_minutes=600),
            registry=registry,
            grant_id="g-1",
            action="ship_finding",
            subject="f-1",
        )
        decision = apply_finding_gate(
            true_finding(),
            registry=registry,
            grant_id="g-1",
            action="ship_finding",
            subject="f-2",
        )
        self.assertTrue(decision.shipped)

    def test_a_shipped_finding_records_no_refusal(self):
        from refusal_hold_wiring import RefusalHoldRegistry

        registry = RefusalHoldRegistry()
        apply_finding_gate(
            true_finding(),
            registry=registry,
            grant_id="g-1",
            action="ship_finding",
            subject="f-1",
        )
        result = registry.check("g-1", "ship_finding", "f-1")
        self.assertFalse(result.blocked)

    def test_the_finding_digest_is_stable_and_distinguishing(self):
        first = finding_gate.finding_digest(true_finding())
        second = finding_gate.finding_digest(true_finding())
        other = finding_gate.finding_digest(true_finding(impact="something else"))
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(first.startswith("sha256:"))

    def test_the_gate_decision_names_the_verdict_and_the_finding(self):
        finding = true_finding()
        decision = apply_finding_gate(finding)
        self.assertIsInstance(decision, finding_gate.GateDecision)
        self.assertIs(decision.finding, finding)
        self.assertEqual(decision.verdict.outcome, VERDICT_PASS)
        self.assertIn("verdict", decision.as_dict())


class DesignDocTests(unittest.TestCase):
    """The design doc states what the gate does."""

    @classmethod
    def setUpClass(cls):
        from pathlib import Path

        root = Path(__file__).resolve().parents[3]
        cls.doc = (root / "docs" / "design" / "bughunter-finding-gate.md").read_text(
            encoding="utf-8"
        )

    def test_the_doc_states_the_seven_questions(self):
        for question in finding_gate.QUESTIONS:
            self.assertIn(question, self.doc)

    def test_the_doc_states_the_verdict_enum(self):
        for verdict in (
            VERDICT_PASS,
            VERDICT_KILL,
            VERDICT_CHAIN_REQUIRED,
            VERDICT_DOWNGRADE,
        ):
            self.assertIn(verdict, self.doc)

    def test_the_doc_states_the_pre_gate_and_the_layer_ordering_trap(self):
        self.assertIn("layer-ordering trap", self.doc)
        self.assertIn("pre-gate", self.doc)
        self.assertIn("ten minutes", self.doc)

    def test_the_doc_states_the_wiring_point(self):
        self.assertIn("refusal-hold seam", self.doc)
        self.assertIn("apply_finding_gate", self.doc)

    def test_the_doc_names_the_source_and_marks_the_extension(self):
        self.assertIn("Claude-BugHunter", self.doc)
        self.assertIn("adapted from", self.doc)
        self.assertIn("Northstar's own", self.doc)


class SecondHalfGuardTests(unittest.TestCase):
    """The guard arms the original suite never reached.

    The mutant census of ``finding_gate.py`` stood at **killed 18/26**:
    eight mutants survived, and every one of them is a guard arm that no
    existing test drove.  Each test below names the mutant it kills.

    The pattern behind all eight is the one this repo calls the
    **double-guard**: a guard written as two halves joined by ``or`` (or
    a bound written as ``<``), where the suite exercises one half and the
    other half is untested.  The surviving arm is invisible to a reader
    of the suite: the tests look complete, and the mutant says the guard
    is looser than it reads.
    """

    # -- the ``repro_minutes`` type guard -------------------------------

    def test_a_boolean_repro_time_is_refused(self):
        """``or@273``: the BOOLEAN half of the type guard.

        The guard is::

            if isinstance(minutes, bool) or not isinstance(minutes, int):

        A ``bool`` IS an ``int`` in Python, so ``isinstance(True, int)`` is
        True and the ``not isinstance(...)`` half does NOT refuse a
        boolean.  Only the explicit boolean half does.  The existing
        suite feeds ``45``, ``None`` and ``600`` -- all non-booleans --
        so under the mutant (``or`` -> ``and``) the boolean half is never
        consulted and a boolean repro time is accepted.

        A boolean repro time is a repro time of 0 or 1: it says "one
        minute" when the caller meant "yes".  The gate must refuse it.
        """
        for value in (True, False):
            with self.subTest(repro_minutes=value):
                with self.assertRaises(FindingGateError) as caught:
                    true_finding(repro_minutes=value)
                self.assertIn("repro_minutes", str(caught.exception))

    def test_a_boolean_repro_time_is_refused_even_when_it_would_pass(self):
        """``or@273``: the control -- the refusal is not an accident.

        ``True`` compares as ``1``, which is under ten minutes, so a
        boolean would sail through the pre-gate if the type guard let it
        through.  This pins that the refusal happens at the TYPE check
        and not because the pre-gate happened to kill the finding.
        """
        with self.assertRaises(FindingGateError):
            true_finding(repro_minutes=True)

    def test_a_non_integer_repro_time_is_refused(self):
        """``or@273``: the OTHER half -- a non-integer is refused too.

        The mutant turns ``or`` into ``and``, so BOTH halves must be
        driven: the boolean (above) and the non-integer.  Under the
        mutant the non-integer half is the only one left, and a float
        such as ``10.5`` would be accepted.
        """
        for value in (10.5, 2.0, "10", [10]):
            with self.subTest(repro_minutes=value):
                with self.assertRaises(FindingGateError):
                    true_finding(repro_minutes=value)

    # -- the ``repro_minutes`` bound ------------------------------------

    def test_a_zero_repro_time_is_accepted(self):
        """``lt@277``: the ZERO boundary of the non-negative check.

        The guard is ``if minutes < 0:``.  The mutant makes it
        ``minutes <= 0``.  The two differ at exactly ONE value: zero.
        The existing suite feeds ``45``, ``None``, ``600`` and ``10`` --
        none of them zero -- so under the mutant a finding that claims to
        reproduce in zero minutes is refused.

        Zero minutes is legal: it says the attack needs no time at all.
        It is under ten minutes, so the pre-gate must let it through.
        """
        finding = true_finding(repro_minutes=0)
        self.assertEqual(finding.repro_minutes, 0)
        verdict = evaluate_finding(finding)
        self.assertEqual(verdict.outcome, VERDICT_PASS)

    def test_a_negative_repro_time_is_refused(self):
        """``lt@277``: the control -- the bound still refuses negatives.

        Without this, "zero is accepted" could be satisfied by a guard
        that accepts everything.  A negative repro time is a contradiction
        -- time does not run backwards -- and must be refused.
        """
        for value in (-1, -600):
            with self.subTest(repro_minutes=value):
                with self.assertRaises(FindingGateError) as caught:
                    true_finding(repro_minutes=value)
                self.assertIn("negative", str(caught.exception))

    # -- the request-shape guard ----------------------------------------

    def test_a_single_token_step_is_not_a_request(self):
        """``gt@375``: the ONE-token boundary of the target guard.

        The line is::

            rest = head[1] if len(head) > 1 else ""

        The mutant makes it ``len(head) >= 1``, which for a one-token
        step reads ``head[1]`` -- an IndexError -- instead of taking the
        ``else`` branch.  The existing suite never feeds a step that is
        a single token, so under the mutant that arm is never reached.

        A single token names a METHOD but no TARGET, so it cannot be
        sent: it is not a request.
        """
        self.assertFalse(finding_gate._is_real_request("GET"))
        self.assertFalse(finding_gate._is_real_request("POST"))
        self.assertFalse(finding_gate._is_real_request("OPTIONS"))

    def test_a_single_token_step_is_killed_by_the_gate(self):
        """``gt@375``: the same boundary, seen through the gate.

        The private helper's answer is the same answer the gate gives:
        a finding whose only step is a bare method is killed at q1
        because the step cannot be sent.
        """
        verdict = evaluate_finding(
            true_finding(attacker_steps=("GET",))
        )
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("real requests", verdict.reason)

    def test_a_step_with_a_method_and_a_target_is_a_request(self):
        """``gt@375``: the control -- a two-token step IS a request.

        The mutant must not be satisfiable by a guard that refuses
        everything, so this pins the positive case: two tokens make a
        request, and the gate lets it through.
        """
        self.assertTrue(finding_gate._is_real_request("GET /api/import"))
        self.assertTrue(finding_gate._is_real_request("POST /api/import {\"rows\": 1}"))
        verdict = evaluate_finding(
            true_finding(attacker_steps=("GET /api/import",))
        )
        self.assertEqual(verdict.outcome, VERDICT_PASS)

    def test_an_empty_step_is_not_a_request(self):
        """``retF@368``: the EMPTY-STEP arm.

        The guard is ``if not step: return False``.  The mutant turns the
        ``return False`` into ``return True``, so an empty step would be
        accepted as a request.  The existing suite feeds a PROSE step,
        which is refused by a LATER guard, so it cannot tell the empty
        arm from the prose arm.

        An empty step is not a request: there is nothing to send.
        """
        self.assertFalse(finding_gate._is_real_request(""))
        self.assertFalse(finding_gate._is_real_request("   "))

    def test_a_whitespace_only_step_is_killed_by_the_gate(self):
        """``retF@368``: the same arm, through the gate.

        A whitespace-only step is stripped to the empty string by
        ``_steps_tuple``, so it reaches the guard as ``""`` -- which is
        exactly the arm above.
        """
        verdict = evaluate_finding(true_finding(attacker_steps=("   ",)))
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("real requests", verdict.reason)

    def test_a_method_with_no_target_is_not_a_request(self):
        """``retF@377``: the NO-TARGET arm.

        The guard is::

            rest = head[1] if len(head) > 1 else ""
            if not rest:
                return False

        The mutant turns that ``return False`` into ``return True``, so a
        step that names a method but no target would be accepted as a
        request.  The existing suite never feeds a method-only step, so
        this arm is untested.
        """
        self.assertFalse(finding_gate._is_real_request("GET"))

    def test_a_target_that_is_not_a_path_is_not_a_request(self):
        """``retF@380``: the NON-PATH-TARGET arm.

        The guard is::

            if not target.startswith("/") and "://" not in target:
                return False

        The mutant turns that ``return False`` into ``return True``, so a
        target that is neither a path nor a URL would be accepted.  The
        existing suite's prose step is refused EARLIER (its method is not
        an HTTP method), so it cannot reach this arm.

        A target that is neither a path nor a URL names nothing that can
        be requested.
        """
        self.assertFalse(finding_gate._is_real_request("GET api/import"))
        self.assertFalse(finding_gate._is_real_request("GET import"))

    def test_an_absolute_url_target_is_a_request(self):
        """``retF@380``: the control -- a URL target IS accepted.

        The ``"://" not in target`` half of the guard must keep working:
        the mutant must not be satisfiable by a guard that refuses every
        target.
        """
        self.assertTrue(finding_gate._is_real_request("GET http://host/api"))
        self.assertTrue(finding_gate._is_real_request("GET https://host/api"))

    # -- the impact-proof guard -----------------------------------------

    def test_no_proof_kind_is_killed_even_with_proof_text(self):
        """``or@538``: the "NO PROOF KIND" half of the guard.

        The guard is::

            if kind == PROOF_NONE or not finding.impact_proof.strip():

        The two halves are independent: a finding can name no proof KIND
        while carrying proof TEXT (a caller that filled in the text and
        left the kind at its default), and it can name a kind with no
        text.  The existing suite only feeds the case where BOTH are
        empty, so under the mutant (``or`` -> ``and``) the first half is
        never decisive and a kind-less finding with proof text survives
        into q6's later branches.

        A finding that names no proof kind has proved nothing, whatever
        text it carries: the kind is what says HOW the impact was shown.
        """
        finding = true_finding(
            impact_proof="the response body carried another tenant's row id 42",
            impact_proof_kind=PROOF_NONE,
        )
        verdict = evaluate_finding(finding)
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("technically possible", verdict.reason)

    def test_a_proof_kind_with_no_text_is_killed(self):
        """``or@538``: the OTHER half -- the text arm, driven too.

        The mutant turns ``or`` into ``and``, so BOTH halves must be
        driven.  A finding that names a proof kind but carries no text
        has no evidence either, and must be killed.
        """
        verdict = evaluate_finding(
            true_finding(impact_proof="", impact_proof_kind=PROOF_CONCRETE)
        )
        self.assertEqual(verdict.outcome, VERDICT_KILL)
        self.assertIn("technically possible", verdict.reason)

