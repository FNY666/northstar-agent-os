"""Tests for edge_memory_combo: gate verdicts with bitemporal memory context."""

import unittest

from edge_gate import EdgeGate, HumanConfirmation
from edge_memory_combo import (
    DENIAL_OUTCOMES,
    EDGE_MEMORY_COMBO_VERSION,
    RULE_MEMORY_ESCALATED,
    SCHEMA_PIN,
    VALID_OUTCOMES,
    EdgeMemoryGate,
    MemoryAwareDecision,
)
from memory_bitemporal import BitemporalMemoryStore


def make_combo(**kwargs):
    gate = EdgeGate(irreversible_allowlist=["newsletter.send"])
    store = BitemporalMemoryStore()
    return EdgeMemoryGate(gate, store, **kwargs), store


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(EDGE_MEMORY_COMBO_VERSION, "edge-memory-combo.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.edge-memory-combo.v1")

    def test_valid_outcomes(self):
        self.assertEqual(
            VALID_OUTCOMES,
            {"allowed", "denied", "human_confirmed", "human_declined"},
        )

    def test_denial_outcomes_subset(self):
        self.assertTrue(DENIAL_OUTCOMES <= VALID_OUTCOMES)


class ConstructorTests(unittest.TestCase):
    def test_default_threshold(self):
        combo, _ = make_combo()
        self.assertEqual(combo.denial_threshold, 1)

    def test_custom_threshold(self):
        combo, _ = make_combo(denial_threshold=3)
        self.assertEqual(combo.denial_threshold, 3)

    def test_bad_gate_type(self):
        with self.assertRaises(TypeError):
            EdgeMemoryGate("not-a-gate", BitemporalMemoryStore())

    def test_bad_store_type(self):
        with self.assertRaises(TypeError):
            EdgeMemoryGate(EdgeGate(), object())

    def test_zero_threshold(self):
        with self.assertRaises(ValueError):
            EdgeMemoryGate(EdgeGate(), BitemporalMemoryStore(), denial_threshold=0)

    def test_bool_threshold(self):
        with self.assertRaises(ValueError):
            EdgeMemoryGate(EdgeGate(), BitemporalMemoryStore(), denial_threshold=True)


class BasePassthroughTests(unittest.TestCase):
    def test_allow_without_history(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({"action_type": "db.query"}, seq=1)
        self.assertEqual(decision.verdict, "allow")
        self.assertEqual(decision.base_verdict, "allow")
        self.assertEqual(decision.memory_denials, 0)

    def test_allowlisted_irreversible_allowed(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({"action_type": "newsletter.send"}, seq=1)
        self.assertEqual(decision.verdict, "allow")

    def test_physical_requires_human(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({"action_type": "robot.move_to"}, seq=1)
        self.assertEqual(decision.verdict, "require_human")
        self.assertEqual(decision.base_verdict, "require_human")

    def test_malformed_denied(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({}, seq=1)
        self.assertEqual(decision.verdict, "deny")

    def test_check_returns_verdict_string(self):
        combo, _ = make_combo()
        self.assertEqual(combo.check({"action_type": "db.query"}, seq=1), "allow")

    def test_check_never_raises(self):
        combo, _ = make_combo()
        for bad in (None, 42, [], {"action_type": 99}):
            self.assertIn(combo.check(bad, seq=1), {"allow", "deny", "require_human"})


class EscalationTests(unittest.TestCase):
    def test_denial_escalates_allow(self):
        combo, store = make_combo()
        action = {"action_type": "newsletter.send"}
        combo.note_outcome(action, "human_declined", 1)
        decision = combo.check_detailed(action, seq=2)
        self.assertEqual(decision.base_verdict, "allow")
        self.assertEqual(decision.verdict, "require_human")
        self.assertEqual(decision.rule, RULE_MEMORY_ESCALATED)
        self.assertEqual(decision.memory_denials, 1)

    def test_denied_outcome_also_escalates(self):
        combo, _ = make_combo()
        action = {"action_type": "newsletter.send"}
        combo.note_outcome(action, "denied", 1)
        decision = combo.check_detailed(action, seq=2)
        self.assertEqual(decision.verdict, "require_human")

    def test_confirmation_outcome_does_not_escalate(self):
        combo, _ = make_combo()
        action = {"action_type": "newsletter.send"}
        combo.note_outcome(action, "human_confirmed", 1)
        decision = combo.check_detailed(action, seq=2)
        self.assertEqual(decision.verdict, "allow")

    def test_threshold_two_needs_two_denials(self):
        combo, _ = make_combo(denial_threshold=2)
        action = {"action_type": "newsletter.send"}
        combo.note_outcome(action, "human_declined", 1)
        still_allow = combo.check_detailed(action, seq=2)
        self.assertEqual(still_allow.verdict, "allow")
        combo.note_outcome(action, "human_declined", 3)
        escalated = combo.check_detailed(action, seq=4)
        self.assertEqual(escalated.verdict, "require_human")
        self.assertEqual(escalated.memory_denials, 2)

    def test_other_action_type_unaffected(self):
        combo, _ = make_combo()
        combo.note_outcome({"action_type": "newsletter.send"}, "human_declined", 1)
        decision = combo.check_detailed({"action_type": "db.query"}, seq=2)
        self.assertEqual(decision.verdict, "allow")
        self.assertEqual(decision.memory_denials, 0)

    def test_require_human_base_stays(self):
        combo, _ = make_combo()
        action = {"action_type": "db.drop"}
        combo.note_outcome(action, "human_declined", 1)
        decision = combo.check_detailed(action, seq=2)
        self.assertEqual(decision.base_verdict, "require_human")
        self.assertEqual(decision.verdict, "require_human")
        # No escalation rule: already at max restrictiveness.
        self.assertNotEqual(decision.rule, RULE_MEMORY_ESCALATED)

    def test_deny_never_escalates(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({}, seq=1)
        self.assertEqual(decision.verdict, "deny")

    def test_expired_denial_stops_escalating(self):
        combo, store = make_combo()
        action = {"action_type": "newsletter.send"}
        combo.note_outcome(action, "human_declined", 1)
        store.apply_decay(current_seq=100, decay_threshold=10)
        decision = combo.check_detailed(action, seq=101)
        self.assertEqual(decision.verdict, "allow")
        self.assertEqual(decision.memory_denials, 0)

    def test_superseded_denial_stops_escalating(self):
        combo, store = make_combo()
        action = {"action_type": "newsletter.send"}
        record = combo.note_outcome(action, "human_declined", 1)
        store.supersede(
            record.id,
            "edge_gate.decision: action_type=newsletter.send outcome=human_confirmed seq=5",
            5,
        )
        decision = combo.check_detailed(action, seq=6)
        self.assertEqual(decision.verdict, "allow")

    def test_non_marker_records_ignored(self):
        combo, store = make_combo()
        store.write("the agent was declined a db.drop once", 1)
        decision = combo.check_detailed({"action_type": "db.query"}, seq=2)
        self.assertEqual(decision.verdict, "allow")
        self.assertEqual(decision.memory_denials, 0)


class NoteOutcomeTests(unittest.TestCase):
    def test_note_returns_memory_record(self):
        combo, _ = make_combo()
        record = combo.note_outcome({"action_type": "db.drop"}, "denied", 1)
        self.assertIn("action_type=db.drop", record.content)
        self.assertIn("outcome=denied", record.content)

    def test_note_bad_action_type(self):
        combo, _ = make_combo()
        with self.assertRaises(TypeError):
            combo.note_outcome("not-a-mapping", "denied", 1)

    def test_note_empty_action_type(self):
        combo, _ = make_combo()
        with self.assertRaises(ValueError):
            combo.note_outcome({}, "denied", 1)

    def test_note_bad_outcome(self):
        combo, _ = make_combo()
        with self.assertRaises(ValueError):
            combo.note_outcome({"action_type": "db.drop"}, "maybe", 1)

    def test_note_bad_seq(self):
        combo, _ = make_combo()
        with self.assertRaises(ValueError):
            combo.note_outcome({"action_type": "db.drop"}, "denied", -1)

    def test_note_uses_type_fallback(self):
        combo, _ = make_combo()
        record = combo.note_outcome({"type": "db.drop"}, "denied", 1)
        self.assertIn("action_type=db.drop", record.content)


class ResolveTests(unittest.TestCase):
    def _confirmation(self, action, confirmed, seq):
        return HumanConfirmation.bind(action, seq, confirmed, "op-1")

    def test_resolve_confirmed_notes_history(self):
        combo, _ = make_combo()
        action = {"action_type": "db.drop"}
        confirmation = self._confirmation(action, True, 1)
        verdict = combo.resolve(action, confirmation, current_seq=2)
        self.assertEqual(verdict, "allow")
        # A declined-then-confirmed history is clean: no denial recorded.
        decision = combo.check_detailed(action, seq=3)
        self.assertEqual(decision.verdict, "require_human")  # base gate, not memory
        self.assertEqual(decision.memory_denials, 0)

    def test_resolve_declined_escalates_future(self):
        combo, _ = make_combo()
        gate_only = combo  # reuse inner gate semantics via a fresh allowlisted action
        gate = EdgeGate(irreversible_allowlist=["newsletter.send"])
        store = BitemporalMemoryStore()
        combo = EdgeMemoryGate(gate, store)
        action = {"action_type": "newsletter.send"}
        confirmation = self._confirmation(action, False, 1)
        verdict = combo.resolve(action, confirmation, current_seq=2)
        self.assertEqual(verdict, "deny")
        decision = combo.check_detailed(action, seq=3)
        self.assertEqual(decision.verdict, "require_human")
        self.assertEqual(decision.rule, RULE_MEMORY_ESCALATED)

    def test_resolve_never_raises(self):
        combo, _ = make_combo()
        self.assertEqual(
            combo.resolve("not-a-mapping", "not-a-confirmation", current_seq=1), "deny"
        )


class DecisionRecordTests(unittest.TestCase):
    def test_as_dict_shape(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({"action_type": "db.query"}, seq=7)
        body = decision.as_dict()
        self.assertEqual(body["schema"], SCHEMA_PIN)
        self.assertEqual(body["version"], EDGE_MEMORY_COMBO_VERSION)
        self.assertEqual(body["verdict"], "allow")
        self.assertEqual(body["base_verdict"], "allow")
        self.assertEqual(body["risk"], "reversible")
        self.assertEqual(body["action_type"], "db.query")
        self.assertEqual(body["memory_denials"], 0)
        self.assertEqual(body["seq"], 7)

    def test_decision_is_frozen(self):
        combo, _ = make_combo()
        decision = combo.check_detailed({"action_type": "db.query"}, seq=1)
        with self.assertRaises(Exception):
            decision.verdict = "deny"


class MainSelfCheckTests(unittest.TestCase):
    def test_main_runs(self):
        from edge_memory_combo import main

        main()


if __name__ == "__main__":
    unittest.main()
