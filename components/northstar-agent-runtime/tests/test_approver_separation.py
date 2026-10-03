"""No-self-attestation: the proposer is never its own approver.

The invariant under test is a single sentence: **an action's approver set
excludes the proposer and the proposer's whole delegation subtree, and when
the only available approver is the proposer the card denies instead of
falling back to auto-approve.**
"""
from __future__ import annotations

import unittest

from action_card import (
    APPROVE,
    DENY,
    ActionProvenance,
    build_action_card,
    resolve_card,
)
from approver_separation import (
    RULE_MALFORMED,
    RULE_SELF_APPROVAL,
    RULE_SOCK_PUPPET_DELEGATEE,
    RULE_UNKNOWN_APPROVER,
    SELF_ATTESTATION_DENIED_EVENT,
    check_approver,
    delegation_subtree,
    eligible_approvers,
    proposer_of,
    self_attestation_denied_event,
)


GRAPH = {
    "agent-a": ("agent-a-sub",),
    "agent-a-sub": ("agent-a-sub-sub",),
    "human-ops": ("human-ops-delegate",),
}


class ProposerOfTests(unittest.TestCase):
    def test_direct_actor_is_proposer(self):
        self.assertEqual(proposer_of(agent="agent-a"), "agent-a")

    def test_outermost_principal_is_proposer(self):
        self.assertEqual(
            proposer_of(agent="agent-b", delegation_chain=("principal", "agent-a", "agent-b")),
            "principal",
        )

    def test_blank_chain_falls_back_to_agent(self):
        self.assertEqual(proposer_of(agent="agent-a", delegation_chain=("", " ")), "agent-a")

    def test_blank_everything(self):
        self.assertEqual(proposer_of(agent=""), "")


class SubtreeTests(unittest.TestCase):
    def test_transitive_descendants(self):
        self.assertEqual(
            delegation_subtree("agent-a", GRAPH),
            ("agent-a", "agent-a-sub", "agent-a-sub-sub"),
        )

    def test_leaf_has_only_itself(self):
        self.assertEqual(delegation_subtree("agent-a-sub-sub", GRAPH), ("agent-a-sub-sub",))

    def test_unknown_identity_has_only_itself(self):
        self.assertEqual(delegation_subtree("stranger", GRAPH), ("stranger",))

    def test_cyclic_graph_terminates(self):
        cyclic = {"x": ("y",), "y": ("x", "z"), "z": ("y",)}
        self.assertEqual(set(delegation_subtree("x", cyclic)), {"x", "y", "z"})

    def test_self_loop_is_harmless(self):
        self.assertEqual(delegation_subtree("x", {"x": ("x",)}), ("x",))

    def test_malformed_graph_fails_closed(self):
        self.assertEqual(delegation_subtree("agent-a", "not-a-mapping"), ())
        self.assertEqual(delegation_subtree("agent-a", {"agent-a": "not-a-list"}), ())
        self.assertEqual(delegation_subtree("agent-a", {"agent-a": ("",)}), ())

    def test_blank_proposer_fails_closed(self):
        self.assertEqual(delegation_subtree("", GRAPH), ())


class EligibleApproversTests(unittest.TestCase):
    def test_excludes_proposer_and_subtree(self):
        self.assertEqual(
            eligible_approvers(
                proposer="agent-a",
                approvers=("agent-a", "agent-a-sub", "human-1", "human-2"),
                delegation_graph=GRAPH,
            ),
            ("human-1", "human-2"),
        )

    def test_order_preserved_duplicates_removed(self):
        self.assertEqual(
            eligible_approvers(
                proposer="agent-a",
                approvers=("human-2", "human-1", "human-2"),
                delegation_graph=GRAPH,
            ),
            ("human-2", "human-1"),
        )

    def test_blank_approver_names_skipped(self):
        self.assertEqual(
            eligible_approvers(proposer="agent-a", approvers=("", "human-1")),
            ("human-1",),
        )

    def test_empty_proposer_fails_closed(self):
        self.assertEqual(eligible_approvers(proposer="", approvers=("human-1",)), ())

    def test_malformed_graph_fails_closed(self):
        self.assertEqual(
            eligible_approvers(proposer="agent-a", approvers=("human-1"), delegation_graph=42),
            (),
        )


class CheckApproverTests(unittest.TestCase):
    def test_third_party_allowed(self):
        v = check_approver(
            proposer="agent-a",
            approver_identity="human-1",
            approvers=("human-1", "human-2"),
            delegation_graph=GRAPH,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.failed_rule, "")

    def test_self_approval_denied(self):
        v = check_approver(
            proposer="agent-a",
            approver_identity="agent-a",
            approvers=("agent-a", "human-1"),
            delegation_graph=GRAPH,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, RULE_SELF_APPROVAL)

    def test_sock_puppet_denied(self):
        v = check_approver(
            proposer="agent-a",
            approver_identity="agent-a-sub",
            approvers=("agent-a-sub", "human-1"),
            delegation_graph=GRAPH,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, RULE_SOCK_PUPPET_DELEGATEE)

    def test_deep_sock_puppet_denied(self):
        v = check_approver(
            proposer="agent-a",
            approver_identity="agent-a-sub-sub",
            approvers=("agent-a-sub-sub",),
            delegation_graph=GRAPH,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, RULE_SOCK_PUPPET_DELEGATEE)

    def test_unrelated_delegatee_allowed(self):
        # human-ops-delegate is a delegatee, just not the proposer's.
        v = check_approver(
            proposer="agent-a",
            approver_identity="human-ops-delegate",
            approvers=("human-ops-delegate",),
            delegation_graph=GRAPH,
        )
        self.assertTrue(v.allowed)

    def test_unknown_approver_denied_when_set_given(self):
        v = check_approver(
            proposer="agent-a",
            approver_identity="random-human",
            approvers=("human-1",),
            delegation_graph=GRAPH,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, RULE_UNKNOWN_APPROVER)

    def test_blank_approver_identity_denied(self):
        v = check_approver(proposer="agent-a", approver_identity="  ")
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, RULE_UNKNOWN_APPROVER)

    def test_blank_proposer_denied(self):
        v = check_approver(proposer="", approver_identity="human-1")
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, RULE_MALFORMED)

    def test_no_registered_set_skips_membership_check(self):
        v = check_approver(proposer="agent-a", approver_identity="human-1")
        self.assertTrue(v.allowed)


class AuditEventTests(unittest.TestCase):
    def test_event_shape(self):
        event = self_attestation_denied_event(
            proposer="agent-a",
            approver_identity="agent-a",
            failed_rule=RULE_SELF_APPROVAL,
            reason="self-approval is never evidence",
            card_id="card-1",
            call_id="call-1",
        )
        self.assertEqual(event["event"], SELF_ATTESTATION_DENIED_EVENT)
        self.assertEqual(event["proposer"], "agent-a")
        self.assertEqual(event["approver"], "agent-a")
        self.assertEqual(event["failed_rule"], RULE_SELF_APPROVAL)
        self.assertEqual(event["card_id"], "card-1")
        self.assertEqual(event["call_id"], "call-1")


def _card(**overrides):
    base = {
        "tool": "Write",
        "call_id": "call_01",
        "arguments": {"path": "/tmp/x.txt", "content": "hi"},
        "risk_tier": "standard",
        "provenance": ActionProvenance(agent="agent-a", session_id="s1"),
    }
    base.update(overrides)
    return build_action_card(**base)


class ResolveCardWiringTests(unittest.TestCase):
    def test_only_approver_is_proposer_denies(self):
        card = _card()
        verdict = resolve_card(
            card,
            approver=lambda c: True,  # never consulted
            approver_identity="agent-a",
            registered_approvers=("agent-a",),
        )
        self.assertEqual(verdict.decision, DENY)
        self.assertIn(SELF_ATTESTATION_DENIED_EVENT, verdict.reason)

    def test_only_approver_is_proposer_denies_despite_auto_approve(self):
        # The gate would auto-approve; the separation gate runs first and the
        # card still denies - there is no fallback to auto-approve.
        card = build_action_card(
            tool="Write",
            call_id="call_02",
            arguments={"path": "/tmp/x.txt"},
            risk_tier="standard",
            provenance=ActionProvenance(agent="agent-a"),
            auto_approve_tiers=("standard",),
            auto_approve_enabled=True,
        )
        self.assertTrue(card.gate.auto_approved)
        verdict = resolve_card(
            card,
            approver=lambda c: True,
            approver_identity="agent-a",
            registered_approvers=("agent-a",),
        )
        self.assertEqual(verdict.decision, DENY)
        self.assertIn(SELF_ATTESTATION_DENIED_EVENT, verdict.reason)

    def test_sock_puppet_approver_denies(self):
        card = _card()
        verdict = resolve_card(
            card,
            approver=lambda c: True,
            approver_identity="agent-a-sub",
            registered_approvers=("agent-a-sub", "human-1"),
            delegation_graph=GRAPH,
        )
        self.assertEqual(verdict.decision, DENY)
        self.assertIn(SELF_ATTESTATION_DENIED_EVENT, verdict.reason)

    def test_third_party_approver_consulted(self):
        card = _card()
        seen = []

        def approver(c):
            seen.append(c.call_id)
            return True

        verdict = resolve_card(
            card,
            approver=approver,
            approver_identity="human-1",
            registered_approvers=("human-1", "agent-a"),
            delegation_graph=GRAPH,
        )
        self.assertEqual(verdict.decision, APPROVE)
        self.assertEqual(seen, ["call_01"])

    def test_delegated_chain_proposer_is_outermost(self):
        card = _card(
            provenance=ActionProvenance(
                agent="agent-b",
                delegation_chain=("principal", "agent-a", "agent-b"),
            )
        )
        verdict = resolve_card(
            card,
            approver=lambda c: True,
            approver_identity="principal",
            registered_approvers=("principal", "human-1"),
        )
        self.assertEqual(verdict.decision, DENY)
        self.assertIn(SELF_ATTESTATION_DENIED_EVENT, verdict.reason)

    def test_unknown_approver_identity_denies(self):
        card = _card()
        verdict = resolve_card(
            card,
            approver=lambda c: True,
            registered_approvers=("human-1",),
        )
        self.assertEqual(verdict.decision, DENY)
        self.assertIn(SELF_ATTESTATION_DENIED_EVENT, verdict.reason)

    def test_backward_compatible_without_identities(self):
        # No identity params: the old default-deny behavior is unchanged.
        card = _card()
        verdict = resolve_card(card, approver=lambda c: True)
        self.assertEqual(verdict.decision, APPROVE)
        verdict = resolve_card(card, approver=None)
        self.assertEqual(verdict.decision, DENY)


if __name__ == "__main__":
    unittest.main()
