"""Tests for action_verifier.py: Silent Stop narration-vs-action checks."""

import unittest

from action_verifier import (
    ACTION_VERIFIER_VERSION,
    SCHEMA_PIN,
    ObservedAction,
    SilentStopDetector,
    SilentStopFinding,
    VerbalClaim,
    verify_action,
)


def make_claim(**kw):
    base = {
        "claim_id": "c1",
        "agent_id": "agent-7",
        "action_type": "report",
        "target": "operator",
        "claimed_seq": 100,
    }
    base.update(kw)
    return VerbalClaim(**base)


def make_observed(**kw):
    base = {
        "action_id": "a1",
        "agent_id": "agent-7",
        "action_type": "report",
        "target": "operator",
        "observed_seq": 105,
    }
    base.update(kw)
    return ObservedAction(**base)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ACTION_VERIFIER_VERSION, "action-verifier.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.action-verifier.v1")


class VerbalClaimTests(unittest.TestCase):
    def test_frozen(self):
        c = make_claim()
        with self.assertRaises(AttributeError):
            c.claim_id = "x"  # type: ignore

    def test_empty_claim_id_rejected(self):
        with self.assertRaises(ValueError):
            make_claim(claim_id="  ")

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            make_claim(claimed_seq=-1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            make_claim(claimed_seq=True)

    def test_as_dict_schema(self):
        d = make_claim().as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["claim_id"], "c1")


class ObservedActionTests(unittest.TestCase):
    def test_empty_target_rejected(self):
        with self.assertRaises(ValueError):
            make_observed(target="")

    def test_non_str_digest_rejected(self):
        with self.assertRaises(TypeError):
            make_observed(audit_digest=123)


class VerifyActionTests(unittest.TestCase):
    def test_match_returns_true(self):
        self.assertTrue(verify_action(make_claim(), make_observed()))

    def test_agent_mismatch_returns_false(self):
        self.assertFalse(verify_action(make_claim(), make_observed(agent_id="agent-8")))

    def test_action_type_mismatch_returns_false(self):
        self.assertFalse(verify_action(make_claim(), make_observed(action_type="delete")))

    def test_target_mismatch_returns_false(self):
        self.assertFalse(verify_action(make_claim(), make_observed(target="admin")))

    def test_observed_before_claim_returns_false(self):
        # An action logged before the claim cannot be the claimed action.
        self.assertFalse(verify_action(make_claim(claimed_seq=100), make_observed(observed_seq=99)))

    def test_case_insensitive_match(self):
        self.assertTrue(
            verify_action(make_claim(agent_id="Agent-7"), make_observed(action_type="REPORT"))
        )

    def test_non_claim_raises(self):
        with self.assertRaises(TypeError):
            verify_action("not-a-claim", make_observed())

    def test_non_observed_raises(self):
        with self.assertRaises(TypeError):
            verify_action(make_claim(), "not-observed")


class SilentStopDetectorTests(unittest.TestCase):
    def test_claim_without_action_is_flagged(self):
        det = SilentStopDetector()
        det.register_claim(make_claim())
        findings = det.flag_silent_stops()
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], SilentStopFinding)
        self.assertEqual(findings[0].claim_id, "c1")

    def test_claim_with_matching_action_not_flagged(self):
        det = SilentStopDetector()
        det.register_claim(make_claim())
        det.register_observed(make_observed())
        self.assertEqual(det.flag_silent_stops(), ())

    def test_multiple_claims_partial_flags(self):
        det = SilentStopDetector()
        det.register_claim(make_claim(claim_id="c1"))
        det.register_claim(make_claim(claim_id="c2", action_type="escalate"))
        det.register_observed(make_observed())  # matches c1 only
        findings = det.flag_silent_stops()
        self.assertEqual([f.claim_id for f in findings], ["c2"])

    def test_verified_claims_view(self):
        det = SilentStopDetector()
        det.register_claim(make_claim(claim_id="c1"))
        det.register_claim(make_claim(claim_id="c2", action_type="escalate"))
        det.register_observed(make_observed())
        self.assertEqual([c.claim_id for c in det.verified_claims()], ["c1"])

    def test_unreported_actions_view(self):
        det = SilentStopDetector()
        det.register_claim(make_claim())
        det.register_observed(make_observed())
        det.register_observed(make_observed(action_id="a2", action_type="backup"))
        unreported = det.unreported_actions()
        self.assertEqual([o.action_id for o in unreported], ["a2"])

    def test_register_non_claim_raises(self):
        det = SilentStopDetector()
        with self.assertRaises(TypeError):
            det.register_claim("x")

    def test_register_non_observed_raises(self):
        det = SilentStopDetector()
        with self.assertRaises(TypeError):
            det.register_observed("x")

    def test_len_counts_claims(self):
        det = SilentStopDetector()
        self.assertEqual(len(det), 0)
        det.register_claim(make_claim())
        self.assertEqual(len(det), 1)

    def test_flag_order_is_registration_order(self):
        det = SilentStopDetector()
        det.register_claim(make_claim(claim_id="c2", action_type="escalate"))
        det.register_claim(make_claim(claim_id="c1", action_type="notify"))
        findings = det.flag_silent_stops()
        self.assertEqual([f.claim_id for f in findings], ["c2", "c1"])

    def test_finding_as_dict(self):
        det = SilentStopDetector()
        det.register_claim(make_claim())
        d = det.flag_silent_stops()[0].as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["action_type"], "report")


if __name__ == "__main__":
    unittest.main()
