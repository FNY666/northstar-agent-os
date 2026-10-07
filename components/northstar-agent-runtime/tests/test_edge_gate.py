"""Edge gate: physical/irreversible dispatch needs a human at the boundary.

The invariant under test is a single sentence: **reversible reads flow
through, irreversible actions stop for a human unless explicitly
allowlisted, physical actions always stop for a human, and malformed
input is denied outright — never guessed at.**
"""
from __future__ import annotations

import dataclasses
import unittest

from edge_gate import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_HUMAN,
    GATE_VERSION,
    SCHEMA_PIN,
    ActionRisk,
    EdgeDecision,
    EdgeGate,
    HumanConfirmation,
    action_digest,
    classify_action,
    edge_gate_event,
)


class ClassifyActionTests(unittest.TestCase):
    def test_reversible_read(self):
        self.assertEqual(classify_action({"action_type": "db.query"}), ActionRisk.REVERSIBLE)

    def test_reversible_list(self):
        self.assertEqual(classify_action({"action_type": "fs.list"}), ActionRisk.REVERSIBLE)

    def test_reversible_preview(self):
        self.assertEqual(classify_action({"type": "email.preview"}), ActionRisk.REVERSIBLE)

    def test_irreversible_delete(self):
        self.assertEqual(classify_action({"action_type": "db.delete"}), ActionRisk.IRREVERSIBLE)

    def test_irreversible_send(self):
        self.assertEqual(classify_action({"action_type": "email.send"}), ActionRisk.IRREVERSIBLE)

    def test_irreversible_pay(self):
        self.assertEqual(classify_action({"action_type": "billing.pay_invoice"}), ActionRisk.IRREVERSIBLE)

    def test_irreversible_publish(self):
        self.assertEqual(classify_action({"action_type": "cms.publish"}), ActionRisk.IRREVERSIBLE)

    def test_physical_robot(self):
        self.assertEqual(classify_action({"action_type": "robot.move_to"}), ActionRisk.PHYSICAL)

    def test_physical_iot(self):
        self.assertEqual(classify_action({"action_type": "iot.relay_on"}), ActionRisk.PHYSICAL)

    def test_physical_door(self):
        self.assertEqual(classify_action({"action_type": "building.unlock_door"}), ActionRisk.PHYSICAL)

    def test_physical_wins_over_irreversible(self):
        # "delete" is irreversible but "robot" is physical: most restrictive wins.
        self.assertEqual(
            classify_action({"action_type": "robot.delete_map"}), ActionRisk.PHYSICAL
        )

    def test_unknown_type_is_physical_fail_closed(self):
        self.assertEqual(
            classify_action({"action_type": "frobnicate.quux"}), ActionRisk.PHYSICAL
        )

    def test_empty_type_is_physical(self):
        self.assertEqual(classify_action({"action_type": ""}), ActionRisk.PHYSICAL)

    def test_missing_type_is_physical(self):
        self.assertEqual(classify_action({"other": "x"}), ActionRisk.PHYSICAL)

    def test_non_mapping_is_physical_never_raises(self):
        for bad in (None, 42, "send", ["email.send"], True):
            self.assertEqual(classify_action(bad), ActionRisk.PHYSICAL)

    def test_claimed_risk_is_ignored_no_downgrade_path(self):
        self.assertEqual(
            classify_action({"action_type": "db.delete", "risk": "reversible"}),
            ActionRisk.IRREVERSIBLE,
        )
        self.assertEqual(
            classify_action({"action_type": "robot.move_to", "risk": "reversible"}),
            ActionRisk.PHYSICAL,
        )

    def test_case_insensitive(self):
        self.assertEqual(classify_action({"action_type": "DB.DELETE"}), ActionRisk.IRREVERSIBLE)

    def test_token_matching_not_substring(self):
        # "list_senders" contains "send" as a substring but the token is
        # "senders": must stay reversible.
        self.assertEqual(
            classify_action({"action_type": "crm.list_senders"}), ActionRisk.REVERSIBLE
        )

    def test_deterministic(self):
        a = {"action_type": "email.send"}
        self.assertEqual(classify_action(a), classify_action(dict(a)))


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.gate = EdgeGate(irreversible_allowlist=["newsletter.send"])

    def test_reversible_allows(self):
        self.assertEqual(self.gate.check({"action_type": "db.query"}, {}), DECISION_ALLOW)

    def test_reversible_allows_with_none_context(self):
        self.assertEqual(self.gate.check({"action_type": "db.query"}, None), DECISION_ALLOW)

    def test_irreversible_requires_human(self):
        self.assertEqual(
            self.gate.check({"action_type": "db.delete"}, {}), DECISION_REQUIRE_HUMAN
        )

    def test_irreversible_allowlisted_allows(self):
        self.assertEqual(
            self.gate.check({"action_type": "newsletter.send"}, {}), DECISION_ALLOW
        )

    def test_allowlist_is_case_insensitive(self):
        self.assertEqual(
            self.gate.check({"action_type": "NEWSLETTER.SEND"}, {}), DECISION_ALLOW
        )

    def test_physical_always_requires_human(self):
        self.assertEqual(
            self.gate.check({"action_type": "robot.move_to"}, {}), DECISION_REQUIRE_HUMAN
        )

    def test_physical_not_covered_by_allowlist(self):
        gate = EdgeGate(irreversible_allowlist=["robot.move_to"])
        self.assertEqual(
            gate.check({"action_type": "robot.move_to"}, {}), DECISION_REQUIRE_HUMAN
        )

    def test_unknown_type_requires_human(self):
        self.assertEqual(
            self.gate.check({"action_type": "frobnicate.quux"}, {}), DECISION_REQUIRE_HUMAN
        )

    def test_malformed_empty_mapping_denies(self):
        self.assertEqual(self.gate.check({}, {}), DECISION_DENY)

    def test_malformed_non_mapping_denies(self):
        for bad in (None, 42, "email.send", ["x"]):
            self.assertEqual(self.gate.check(bad, {}), DECISION_DENY)

    def test_malformed_non_string_type_denies(self):
        self.assertEqual(self.gate.check({"action_type": 42}, {}), DECISION_DENY)

    def test_check_never_raises(self):
        for bad in (None, 0, "", [], {}, {"action_type": None}):
            self.gate.check(bad, None)

    def test_check_detailed_carries_rule(self):
        d = self.gate.check_detailed({"action_type": "db.delete"}, {}, seq=7)
        self.assertIsInstance(d, EdgeDecision)
        self.assertEqual(d.verdict, DECISION_REQUIRE_HUMAN)
        self.assertEqual(d.risk, ActionRisk.IRREVERSIBLE)
        self.assertEqual(d.action_type, "db.delete")
        self.assertEqual(d.seq, 7)
        self.assertTrue(d.rule)

    def test_check_detailed_reversible_rule(self):
        d = self.gate.check_detailed({"action_type": "db.query"}, {})
        self.assertEqual(d.rule, "reversible_allow")

    def test_check_detailed_malformed_rule(self):
        d = self.gate.check_detailed({}, {})
        self.assertEqual(d.verdict, DECISION_DENY)
        self.assertEqual(d.rule, "malformed_deny")

    def test_empty_allowlist(self):
        gate = EdgeGate()
        self.assertEqual(
            gate.check({"action_type": "email.send"}, {}), DECISION_REQUIRE_HUMAN
        )


class HumanConfirmationTests(unittest.TestCase):
    def test_frozen(self):
        c = HumanConfirmation.bind({"action_type": "db.delete"}, 3, True, "op-1")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.confirmed = False  # type: ignore[misc]

    def test_bind_fills_digest(self):
        action = {"action_type": "db.delete"}
        c = HumanConfirmation.bind(action, 3, True, "op-1")
        self.assertEqual(c.action_digest, action_digest(action))
        self.assertTrue(c.action_digest.startswith("sha256:"))

    def test_as_dict_shape(self):
        c = HumanConfirmation.bind({"action_type": "db.delete"}, 3, True, "op-1")
        d = c.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], GATE_VERSION)
        self.assertTrue(d["confirmed"])
        self.assertEqual(d["confirmed_by"], "op-1")
        self.assertEqual(d["requested_seq"], 3)

    def test_digest_changes_with_action(self):
        c1 = HumanConfirmation.bind({"action_type": "db.delete"}, 3, True, "op-1")
        c2 = HumanConfirmation.bind({"action_type": "db.drop"}, 3, True, "op-1")
        self.assertNotEqual(c1.action_digest, c2.action_digest)


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.gate = EdgeGate()
        self.action = {"action_type": "db.delete", "table": "users"}

    def _confirm(self, **kw):
        args = {"action": self.action, "requested_seq": 10, "confirmed": True,
                "confirmed_by": "op-1"}
        args.update(kw)
        return HumanConfirmation.bind(args.pop("action"), args["requested_seq"],
                                      args["confirmed"], args["confirmed_by"])

    def test_matching_confirmation_allows(self):
        c = self._confirm()
        self.assertEqual(self.gate.resolve(self.action, c, current_seq=10), DECISION_ALLOW)

    def test_declined_confirmation_denies(self):
        c = self._confirm(confirmed=False)
        self.assertEqual(self.gate.resolve(self.action, c, current_seq=10), DECISION_DENY)

    def test_replayed_confirmation_for_other_action_denies(self):
        c = self._confirm()
        other = {"action_type": "db.drop", "table": "users"}
        self.assertEqual(self.gate.resolve(other, c, current_seq=10), DECISION_DENY)

    def test_tampered_action_denies(self):
        c = self._confirm()
        tampered = {"action_type": "db.delete", "table": "admins"}
        self.assertEqual(self.gate.resolve(tampered, c, current_seq=10), DECISION_DENY)

    def test_anonymous_confirmer_denies(self):
        c = self._confirm(confirmed_by="   ")
        self.assertEqual(self.gate.resolve(self.action, c, current_seq=10), DECISION_DENY)

    def test_non_confirmation_denies(self):
        self.assertEqual(
            self.gate.resolve(self.action, "yes", current_seq=10), DECISION_DENY  # type: ignore[arg-type]
        )

    def test_stale_confirmation_denies(self):
        gate = EdgeGate(max_confirmation_age_seq=5)
        c = self._confirm()
        self.assertEqual(gate.resolve(self.action, c, current_seq=16), DECISION_DENY)

    def test_fresh_confirmation_allows_with_age_bound(self):
        gate = EdgeGate(max_confirmation_age_seq=5)
        c = self._confirm()
        self.assertEqual(gate.resolve(self.action, c, current_seq=14), DECISION_ALLOW)

    def test_confirmation_from_future_denies(self):
        gate = EdgeGate(max_confirmation_age_seq=5)
        c = self._confirm()
        self.assertEqual(gate.resolve(self.action, c, current_seq=9), DECISION_DENY)

    def test_no_age_bound_never_stale(self):
        c = self._confirm()
        self.assertEqual(
            self.gate.resolve(self.action, c, current_seq=10_000), DECISION_ALLOW
        )

    def test_invalid_max_age_rejected(self):
        with self.assertRaises(ValueError):
            EdgeGate(max_confirmation_age_seq=-1)

    def test_resolve_never_raises(self):
        c = self._confirm()
        self.gate.resolve(None, c, current_seq=10)  # type: ignore[arg-type]
        self.gate.resolve(self.action, None, current_seq=10)  # type: ignore[arg-type]


class AuditEventTests(unittest.TestCase):
    def test_require_human_event(self):
        gate = EdgeGate()
        d = gate.check_detailed({"action_type": "db.delete"}, {}, seq=4)
        ev = edge_gate_event(d, seq=4)
        self.assertEqual(ev["event"], "edge_gate.require_human")
        self.assertEqual(ev["verdict"], DECISION_REQUIRE_HUMAN)
        self.assertEqual(ev["risk"], "irreversible")
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_confirmed_event_pins_confirmation(self):
        gate = EdgeGate()
        action = {"action_type": "db.delete"}
        c = HumanConfirmation.bind(action, 10, True, "op-1")
        d = EdgeDecision(verdict=DECISION_ALLOW, risk=ActionRisk.IRREVERSIBLE,
                         action_type="db.delete", rule="confirmation_ok", seq=11)
        ev = edge_gate_event(d, confirmation=c, seq=11)
        self.assertEqual(ev["event"], "edge_gate.human_confirmed")
        self.assertEqual(ev["confirmation"]["confirmed_by"], "op-1")
        self.assertEqual(ev["confirmation"]["action_digest"], c.action_digest)

    def test_denied_event(self):
        d = EdgeDecision(verdict=DECISION_DENY, risk=ActionRisk.PHYSICAL,
                         action_type="", rule="malformed_deny", seq=1)
        ev = edge_gate_event(d, seq=1)
        self.assertEqual(ev["event"], "edge_gate.denied")


class MainSmokeTests(unittest.TestCase):
    def test_main_runs(self):
        from edge_gate import main
        main()  # raises SystemExit(1) only on corpus mismatch


if __name__ == "__main__":
    unittest.main()
