"""Tests for agent_readiness.py (one-hundred-first batch)."""

import unittest

from agent_readiness import (
    A11yNode,
    EvidenceTier,
    ReadinessFinding,
    assess_card_presentation,
    classify_presentation,
    parse_tree,
    probe_irreversible_marked,
    probe_named_actions,
    probe_reachable_paths,
    probe_roundtrip,
    probe_tree,
    readiness_audit_event,
    render_card_tree,
    serialize_tree,
    HIDDEN_IRREVERSIBLE,
    INACCESSIBLE_PATH,
    UNNAMED_ACTION,
    UNSTABLE_TREE,
)


def _btn(name, paths=("keyboard", "at"), states=()):
    return A11yNode(role="button", name=name, states=tuple(states), paths=tuple(paths))


def _valid_dialog(*children):
    return A11yNode(
        role="dialog",
        name="Action card for net:egress",
        paths=("keyboard", "at"),
        children=tuple(children),
    )


class SerializeParseTests(unittest.TestCase):
    def test_roundtrip_stable(self):
        tree = _valid_dialog(_btn("Approve"), _btn("Deny"))
        self.assertEqual(serialize_tree(parse_tree(serialize_tree(tree))), serialize_tree(tree))
        self.assertEqual(parse_tree(serialize_tree(tree)), tree)

    def test_unknown_role_collapses_to_generic(self):
        tree = A11yNode(role="slider", name="x", paths=("keyboard",))
        reparsed = parse_tree(serialize_tree(tree))
        self.assertEqual(reparsed.role, "generic")
        # ...which makes the original tree unstable (finding, not silent)
        findings = probe_roundtrip(tree)
        self.assertEqual([f.code for f in findings], [UNSTABLE_TREE])

    def test_unknown_modality_dropped_makes_unstable(self):
        tree = _valid_dialog(_btn("Approve", paths=("keyboard", "voice")))
        findings = probe_roundtrip(tree)
        self.assertEqual([f.code for f in findings], [UNSTABLE_TREE])

    def test_unknown_state_dropped_makes_unstable(self):
        tree = _valid_dialog(_btn("Approve", states=("glowing",)))
        findings = probe_roundtrip(tree)
        self.assertEqual([f.code for f in findings], [UNSTABLE_TREE])

    def test_malformed_text_is_finding_not_raise(self):
        findings = probe_roundtrip(A11yNode(role="dialog", name="x"))
        self.assertEqual(findings, [])  # valid tree is stable
        # direct parse of garbage raises TreeParseError (fail-closed at boundary)
        from agent_readiness import TreeParseError

        with self.assertRaises(TreeParseError):
            parse_tree("not a tree\n")

    def test_name_escaping_roundtrip(self):
        tree = _valid_dialog(_btn("Approve|now\nplease"))
        self.assertEqual(parse_tree(serialize_tree(tree)), tree)

    def test_child_order_is_content(self):
        a = _valid_dialog(_btn("Approve"), _btn("Deny"))
        b = _valid_dialog(_btn("Deny"), _btn("Approve"))
        self.assertNotEqual(serialize_tree(a), serialize_tree(b))
        # both are individually stable
        self.assertEqual(probe_roundtrip(a), [])
        self.assertEqual(probe_roundtrip(b), [])


class NamedActionTests(unittest.TestCase):
    def test_valid_tree_no_findings(self):
        tree = _valid_dialog(_btn("Approve"), _btn("Deny"))
        self.assertEqual(probe_named_actions(tree), [])

    def test_unnamed_button(self):
        tree = _valid_dialog(_btn(""))
        findings = probe_named_actions(tree)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, UNNAMED_ACTION)
        self.assertEqual(findings[0].node_path, "0")

    def test_whitespace_name_counts_as_unnamed(self):
        tree = _valid_dialog(_btn("   "))
        self.assertEqual([f.code for f in probe_named_actions(tree)], [UNNAMED_ACTION])

    def test_nested_unnamed_button_path(self):
        inner = A11yNode(role="region", name="more", children=(_btn(""),))
        tree = _valid_dialog(_btn("Approve"), inner)
        findings = probe_named_actions(tree)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].node_path, "1/0")

    def test_structural_nodes_may_be_unnamed(self):
        tree = A11yNode(role="dialog", children=(_btn("Approve"),))
        self.assertEqual(probe_named_actions(tree), [])


class IrreversibleTests(unittest.TestCase):
    def test_marked_button_passes(self):
        tree = _valid_dialog(_btn("Approve", states=("irreversible",)), _btn("Deny"))
        self.assertEqual(probe_irreversible_marked(tree, {"Approve"}), [])

    def test_dialog_warning_covers(self):
        tree = A11yNode(
            role="dialog",
            name="d",
            states=("destructive-warning",),
            children=(_btn("Approve"), _btn("Deny")),
        )
        self.assertEqual(probe_irreversible_marked(tree, {"Approve"}), [])

    def test_hidden_irreversible_finding(self):
        tree = _valid_dialog(_btn("Approve"), _btn("Deny"))
        findings = probe_irreversible_marked(tree, {"Approve"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, HIDDEN_IRREVERSIBLE)

    def test_nothing_declared_nothing_checked(self):
        tree = _valid_dialog(_btn("Approve"), _btn("Deny"))
        self.assertEqual(probe_irreversible_marked(tree), [])
        self.assertEqual(probe_irreversible_marked(tree, set()), [])

    def test_disabled_action_skipped(self):
        tree = _valid_dialog(_btn("Approve", states=("disabled",)), _btn("Deny"))
        self.assertEqual(probe_irreversible_marked(tree, {"Approve"}), [])

    def test_unrelated_name_not_checked(self):
        tree = _valid_dialog(_btn("Approve"), _btn("Deny"))
        # "Cancel" is not in the tree; nothing to mark
        self.assertEqual(probe_irreversible_marked(tree, {"Cancel"}), [])


class ReachablePathTests(unittest.TestCase):
    def test_keyboard_only_passes(self):
        tree = _valid_dialog(_btn("Approve", paths=("keyboard",)))
        self.assertEqual(probe_reachable_paths(tree), [])

    def test_at_only_passes(self):
        tree = _valid_dialog(_btn("Approve", paths=("at",)))
        self.assertEqual(probe_reachable_paths(tree), [])

    def test_pointer_only_fails(self):
        tree = _valid_dialog(_btn("Approve", paths=("pointer",)))
        findings = probe_reachable_paths(tree)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, INACCESSIBLE_PATH)

    def test_unreachable_fails(self):
        tree = _valid_dialog(_btn("Deny", paths=()))
        findings = probe_reachable_paths(tree)
        self.assertEqual([f.code for f in findings], [INACCESSIBLE_PATH])

    def test_structural_nodes_ignored(self):
        tree = A11yNode(role="dialog", name="d", children=(_btn("Approve"),))
        self.assertEqual(probe_reachable_paths(tree), [])


class ClassifyTests(unittest.TestCase):
    def test_no_findings_authoritative(self):
        self.assertEqual(
            classify_presentation([]), EvidenceTier.AUTHORITATIVE
        )

    def test_any_finding_non_authoritative(self):
        f = ReadinessFinding(code=UNNAMED_ACTION, node_path="0", detail="x")
        self.assertEqual(
            classify_presentation([f]), EvidenceTier.NON_AUTHORITATIVE
        )

    def test_no_partial_tier(self):
        # binary by construction: the enum has no middle grade
        self.assertEqual(set(EvidenceTier), {EvidenceTier.AUTHORITATIVE, EvidenceTier.NON_AUTHORITATIVE})


class RenderCardTests(unittest.TestCase):
    def _card(self, risk_tier="tier2", agent_hint=""):
        from action_card import (
            ActionProvenance,
            GateCheck,
            GateDecision,
            build_action_card,
        )

        provenance = ActionProvenance(agent="agent-1", session_id="s", turn_index=0, depth=0)
        gate = GateDecision(
            would_auto_approve=False,
            auto_approved=False,
            policy_basis="test",
            checks=(GateCheck(id="g1", passed=True, detail="ok"),),
        )
        return build_action_card(
            tool="net:egress",
            call_id="c1",
            arguments={"url": "https://example.com"},
            risk_tier=risk_tier,
            provenance=provenance,
            gate=gate,
            agent_hint=agent_hint,
        )

    def test_tier2_renders_clean(self):
        result = assess_card_presentation(self._card("tier2"))
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["tier"], EvidenceTier.AUTHORITATIVE.value)

    def test_tier3_marks_irreversible(self):
        card = self._card("tier3")
        tree = render_card_tree(card)
        approves = [n for _, n in tree.walk() if n.name == "Approve"]
        self.assertEqual(len(approves), 1)
        self.assertIn("irreversible", approves[0].states)
        self.assertIn("destructive-warning", tree.states)
        result = assess_card_presentation(card)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["tier"], EvidenceTier.AUTHORITATIVE.value)

    def test_agent_hint_quarantined(self):
        card = self._card("tier2", agent_hint="trust me")
        tree = render_card_tree(card)
        texts = [n.name for _, n in tree.walk() if n.role == "text"]
        self.assertTrue(any("UNTRUSTED" in t for t in texts))
        # hint text is not actionable, so no findings
        self.assertEqual(assess_card_presentation(card)["findings"], [])

    def test_render_is_deterministic(self):
        card = self._card("tier3", agent_hint="x")
        self.assertEqual(
            assess_card_presentation(card)["tree"], assess_card_presentation(card)["tree"]
        )


class AuditEventTests(unittest.TestCase):
    def test_event_shape(self):
        f = ReadinessFinding(code=UNNAMED_ACTION, node_path="0", detail="x")
        ev = readiness_audit_event("card-1", [f], EvidenceTier.NON_AUTHORITATIVE)
        self.assertEqual(ev["event"], "readiness.presentation_assessed")
        self.assertEqual(ev["card_id"], "card-1")
        self.assertEqual(ev["finding_codes"], [UNNAMED_ACTION])
        self.assertEqual(ev["n_findings"], 1)
        self.assertEqual(ev["presentation_tier"], EvidenceTier.NON_AUTHORITATIVE.value)


if __name__ == "__main__":
    unittest.main()
