"""Tests for per_action_autonomy_probes."""

import unittest

import per_action_autonomy_probes as paa


def _digest(arguments):
    return "sha256:" + __import__("hashlib").sha256(
        __import__("json").dumps(
            arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _action(action_id="a1", tool="db.read", args=None, level=paa.LEVEL_ACT_WITH_APPROVAL,
            ceiling=()):
    return paa.AutonomyAction(
        action_id=action_id,
        tool_name=tool,
        arguments_digest=_digest(args if args is not None else {"k": "v"}),
        level=level,
        ceiling=tuple(ceiling),
    )


def _approval_for(action, approver="human-1"):
    return paa.ImmutableApproval(
        action_id=action.action_id,
        immutable_object_digest=action.immutable_object_digest,
        approver=approver,
    ).pinned()


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names_unique(self):
        names = list(paa.attack_probe_names()) + list(paa.benign_probe_names())
        self.assertEqual(len(names), len(set(names)))

    def test_required_keys(self):
        for probe in (*paa.PER_ACTION_AUTONOMY_PROBES, *paa.PER_ACTION_AUTONOMY_BENIGN):
            for key in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(key, probe, f"{probe['probe']} missing {key}")

    def test_expected_outcomes(self):
        outcomes = paa.expected_outcomes()
        self.assertTrue(all(outcomes[n] == "deny" for n in paa.attack_probe_names()))
        self.assertTrue(all(outcomes[n] == "allow" for n in paa.benign_probe_names()))

    def test_deny_side_keywords_on_all_attacks(self):
        keywords = paa.DENY_SIDE_KEYWORDS
        for probe in paa.PER_ACTION_AUTONOMY_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in keywords),
                f"{probe['probe']} gate_interaction names no deny-side keyword",
            )

    def test_family_counts(self):
        self.assertEqual(len(paa.probes_in_family("autonomy-levels")), 4)
        self.assertEqual(len(paa.probes_in_family("immutable-approval")), 4)
        self.assertEqual(len(paa.probes_in_family("action-gates")), 2)
        self.assertEqual(len(paa.PER_ACTION_AUTONOMY_PROBES), 10)
        self.assertEqual(len(paa.PER_ACTION_AUTONOMY_BENIGN), 3)

    def test_source_lists_all_probes(self):
        listed = set(paa.PER_ACTION_AUTONOMY_SOURCE["probes"])
        self.assertEqual(listed, set(paa.attack_probe_names()))
        self.assertEqual(
            set(paa.PER_ACTION_AUTONOMY_SOURCE["benign"]),
            set(paa.benign_probe_names()),
        )

    def test_probe_by_name(self):
        probe = paa.probe_by_name("immutable-params-changed")
        self.assertEqual(probe["family"], "immutable-approval")
        self.assertEqual(probe["expected"], "deny")
        self.assertEqual(paa.probe_by_name("benign-per-action-levels")["expected"], "allow")
        with self.assertRaises(KeyError):
            paa.probe_by_name("no-such-probe")

    def test_levels_ordered(self):
        self.assertEqual(len(paa.LEVELS), 5)
        self.assertEqual(len(set(paa.LEVELS)), 5)


class RecordValidationTests(unittest.TestCase):
    def test_action_requires_known_level(self):
        with self.assertRaises(paa.PerActionAutonomyError):
            paa.AutonomyAction(
                action_id="a", tool_name="t",
                arguments_digest=_digest({}), level="A9",
            )

    def test_action_requires_digest(self):
        with self.assertRaises(paa.PerActionAutonomyError):
            paa.AutonomyAction(action_id="a", tool_name="t", arguments_digest="nope",
                               level=paa.LEVEL_OBSERVE)

    def test_a3_requires_ceiling(self):
        with self.assertRaises(paa.PerActionAutonomyError):
            _action(level=paa.LEVEL_ACT_WITHIN_CEILING, ceiling=())

    def test_a4_requires_ceiling(self):
        with self.assertRaises(paa.PerActionAutonomyError):
            _action(level=paa.LEVEL_FULL, ceiling=())

    def test_a3_with_ceiling_ok(self):
        action = _action(level=paa.LEVEL_ACT_WITHIN_CEILING, ceiling=("bucket-1",))
        self.assertEqual(action.ceiling, ("bucket-1",))

    def test_blanket_approval_rejected_at_construction(self):
        with self.assertRaises(paa.PerActionAutonomyError):
            paa.ImmutableApproval(
                action_id="a",
                immutable_object_digest=_digest({}),
                approver="human",
                blanket=True,
            )

    def test_approval_requires_digest(self):
        with self.assertRaises(paa.PerActionAutonomyError):
            paa.ImmutableApproval(action_id="a", immutable_object_digest="bad",
                                  approver="human")

    def test_approval_verify_roundtrip(self):
        action = _action()
        approval = _approval_for(action)
        self.assertTrue(paa.verify_approval(approval))

    def test_approval_tamper_fail_closed(self):
        action = _action()
        approval = _approval_for(action)
        tampered = paa.ImmutableApproval(
            action_id=approval.action_id,
            immutable_object_digest=approval.immutable_object_digest,
            approver="attacker",
            digest=approval.digest,
        )
        self.assertFalse(paa.verify_approval(tampered))

    def test_verdict_verify_roundtrip(self):
        action = _action(level=paa.LEVEL_OBSERVE)
        gate = paa.AutonomyGate()
        verdict = gate.decide(action)
        self.assertTrue(paa.verify_verdict(verdict))


class GatePathTests(unittest.TestCase):
    def test_a4_default_denied(self):
        action = _action(level=paa.LEVEL_FULL, ceiling=("db",))
        verdict = paa.AutonomyGate().decide(action)
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.deny_code, paa.DENY_FULL_AUTONOMY_DEFAULT)
        self.assertTrue(paa.verify_verdict(verdict))

    def test_silent_upgrade_denied(self):
        action = _action()
        verdict = paa.AutonomyGate().decide(
            action, level_at_dispatch=paa.LEVEL_ACT_WITHIN_CEILING
        )
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.deny_code, paa.DENY_LEVEL_UPGRADED)

    def test_downgrade_at_dispatch_not_flagged(self):
        # Dispatching *below* the authorized level is not an upgrade.
        action = _action(level=paa.LEVEL_ACT_WITHIN_CEILING, ceiling=("c",))
        verdict = paa.AutonomyGate().decide(action, level_at_dispatch=paa.LEVEL_OBSERVE)
        self.assertEqual(verdict.decision, "proceed")

    def test_unknown_dispatch_level_denied(self):
        action = _action()
        verdict = paa.AutonomyGate().decide(action, level_at_dispatch="A9")
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.deny_code, paa.DENY_LEVEL_UNASSIGNED)

    def test_a2_without_approval_held(self):
        action = _action()
        verdict = paa.AutonomyGate().decide(action)
        self.assertEqual(verdict.decision, "hold")
        self.assertEqual(verdict.deny_code, paa.DENY_LEVEL_UNASSIGNED)

    def test_a2_with_verified_approval_proceeds(self):
        action = _action()
        approval = _approval_for(action)
        verdict = paa.AutonomyGate().decide(action, approval=approval)
        self.assertEqual(verdict.decision, "proceed")
        self.assertIsNone(verdict.deny_code)

    def test_a2_via_registered_approval_proceeds(self):
        action = _action()
        gate = paa.AutonomyGate()
        gate.approve(_approval_for(action))
        verdict = gate.decide(action)
        self.assertEqual(verdict.decision, "proceed")

    def test_unverified_approval_denied(self):
        action = _action()
        bad = paa.ImmutableApproval(
            action_id=action.action_id,
            immutable_object_digest=action.immutable_object_digest,
            approver="human",
            digest=_digest({"forged": True}),
        )
        with self.assertRaises(paa.PerActionAutonomyError):
            paa.AutonomyGate().approve(bad)

    def test_params_changed_invalidates_approval(self):
        action = _action(args={"amount": 5})
        changed = _action(action_id=action.action_id, args={"amount": 5000})
        approval = _approval_for(action)
        verdict = paa.AutonomyGate().decide(changed, approval=approval)
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.deny_code, paa.DENY_IMMUTABLE_MISMATCH)

    def test_approval_transfer_denied(self):
        action_a = _action(action_id="a")
        action_b = _action(action_id="b")
        approval_for_a = _approval_for(action_a)
        verdict = paa.AutonomyGate().decide(action_b, approval=approval_for_a)
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.deny_code, paa.DENY_APPROVAL_TRANSFER)

    def test_standing_grant_denied(self):
        action = _action(level=paa.LEVEL_OBSERVE)
        gate = paa.AutonomyGate()
        first = gate.decide(action)
        self.assertEqual(first.decision, "proceed")
        second = gate.decide(action)
        self.assertEqual(second.decision, "deny")
        self.assertEqual(second.deny_code, paa.DENY_STANDING_GRANT)

    def test_a0_a1_proceed_without_approval(self):
        for level in (paa.LEVEL_OBSERVE, paa.LEVEL_ADVISE):
            verdict = paa.AutonomyGate().decide(_action(level=level, action_id=level))
            self.assertEqual(verdict.decision, "proceed")

    def test_a3_within_ceiling_proceeds(self):
        action = _action(level=paa.LEVEL_ACT_WITHIN_CEILING, ceiling=("bucket-1",))
        verdict = paa.AutonomyGate().decide(action)
        self.assertEqual(verdict.decision, "proceed")
        self.assertIsNone(verdict.deny_code)

    def test_verdict_digest_pins_ceiling(self):
        action = _action(level=paa.LEVEL_ACT_WITHIN_CEILING, ceiling=("c1",))
        verdict = paa.AutonomyGate().decide(action).pinned()
        # A verdict re-derived over a widened ceiling must not verify.
        widened = paa.AutonomyVerdict(
            action_id=verdict.action_id, tool_name=verdict.tool_name,
            arguments_digest=verdict.arguments_digest, level=verdict.level,
            ceiling=("c1", "c2"), decision=verdict.decision,
            deny_code=verdict.deny_code, reason=verdict.reason,
            digest=verdict.digest,
        )
        self.assertFalse(paa.verify_verdict(widened))

    def test_main_runs(self):
        paa.main()


if __name__ == "__main__":
    unittest.main()
