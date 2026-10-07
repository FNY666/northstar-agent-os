"""Tests for scalable_oversight.py."""

import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scalable_oversight import (
    OversightMethod,
    OversightProtocol,
    OversightReport,
    OverseenAction,
    RiskTier,
    SCALABLE_OVERSIGHT_VERSION,
    SCHEMA_PIN,
    StrongEvidence,
    Verdict,
    oversight_audit_event,
)


def make_protocol(**kwargs):
    defaults = dict(method=OversightMethod.DIRECT, threshold=0.5)
    defaults.update(kwargs)
    return OversightProtocol(**defaults)


def make_action(action_id="a1", action_type="newsletter.send",
                tier=RiskTier.LOW, confidence=0.95):
    return OverseenAction(action_id, action_type, tier, confidence)


class TestVersionAndSchema(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SCALABLE_OVERSIGHT_VERSION, "scalable-oversight.v1")

    def test_schema_pin_on_report(self):
        report = make_protocol().oversee(make_action())
        self.assertEqual(report.schema, SCHEMA_PIN)
        self.assertEqual(report.as_dict()["schema"], SCHEMA_PIN)


class TestFrozenRecords(unittest.TestCase):
    def test_action_frozen(self):
        action = make_action()
        with self.assertRaises(FrozenInstanceError):
            action.action_id = "x"

    def test_protocol_frozen(self):
        protocol = make_protocol()
        with self.assertRaises(FrozenInstanceError):
            protocol.threshold = 0.9

    def test_evidence_frozen(self):
        evidence = StrongEvidence(OversightMethod.DEBATE, True, 0.8)
        with self.assertRaises(FrozenInstanceError):
            evidence.confidence = 0.1


class TestValidation(unittest.TestCase):
    def test_threshold_out_of_range(self):
        with self.assertRaises(ValueError):
            make_protocol(threshold=1.5)
        with self.assertRaises(ValueError):
            make_protocol(threshold=-0.1)

    def test_threshold_bool_rejected(self):
        with self.assertRaises(TypeError):
            make_protocol(threshold=True)

    def test_spot_check_rate_validation(self):
        with self.assertRaises(ValueError):
            make_protocol(spot_check_rate=2.0)
        with self.assertRaises(TypeError):
            make_protocol(spot_check_rate="lots")

    def test_deny_above_must_be_tier(self):
        with self.assertRaises(TypeError):
            make_protocol(deny_above="CRITICAL")

    def test_confidence_bool_rejected(self):
        with self.assertRaises(TypeError):
            make_action(confidence=True)

    def test_action_empty_id(self):
        with self.assertRaises(ValueError):
            make_action(action_id="  ")

    def test_oversee_rejects_non_action(self):
        with self.assertRaises(TypeError):
            make_protocol().oversee("not an action")

    def test_review_rejects_bad_evidence(self):
        with self.assertRaises(TypeError):
            make_protocol().review(make_action(), "evidence-ish")


class TestTriage(unittest.TestCase):
    def test_low_risk_high_confidence_approved(self):
        report = make_protocol().oversee(make_action())
        self.assertEqual(report.verdict, Verdict.APPROVED)
        self.assertEqual(report.reason, "within auto-approve envelope")

    def test_critical_denied_by_default(self):
        report = make_protocol().oversee(make_action(tier=RiskTier.CRITICAL, confidence=1.0))
        self.assertEqual(report.verdict, Verdict.DENIED)

    def test_deny_above_high_denies_high_and_critical(self):
        protocol = make_protocol(deny_above=RiskTier.HIGH)
        for tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            report = protocol.oversee(make_action(tier=tier, confidence=1.0))
            self.assertEqual(report.verdict, Verdict.DENIED, tier)

    def test_medium_low_confidence_needs_review(self):
        report = make_protocol().oversee(make_action(tier=RiskTier.MEDIUM, confidence=0.2))
        self.assertEqual(report.verdict, Verdict.NEEDS_REVIEW)
        self.assertIn("debate", report.reason)

    def test_deny_listed_action_type_denied(self):
        protocol = make_protocol(deny_list=("db.drop",))
        report = protocol.oversee(make_action(action_type="db.drop", tier=RiskTier.LOW))
        self.assertEqual(report.verdict, Verdict.DENIED)
        self.assertIn("deny-listed", report.reason)

    def test_low_confidence_raises_risk_score(self):
        low_conf = make_action(confidence=0.1).risk_score()
        high_conf = make_action(confidence=0.99).risk_score()
        self.assertGreater(low_conf, high_conf)

    def test_risk_score_clipped(self):
        score = OverseenAction("x", "y", RiskTier.CRITICAL, 0.0).risk_score()
        self.assertLessEqual(score, 1.0)


class TestSpotCheck(unittest.TestCase):
    def test_spot_check_deterministic(self):
        protocol = make_protocol(spot_check_rate=0.5)
        first = protocol.oversee(make_action(action_id="same-id")).spot_checked
        second = protocol.oversee(make_action(action_id="same-id")).spot_checked
        self.assertEqual(first, second)

    def test_spot_check_rate_zero_never(self):
        protocol = make_protocol(spot_check_rate=0.0)
        for i in range(10):
            report = protocol.oversee(make_action(action_id=f"id-{i}"))
            if report.verdict is Verdict.APPROVED:
                self.assertFalse(report.spot_checked)

    def test_spot_check_rate_one_always(self):
        protocol = make_protocol(spot_check_rate=1.0)
        report = protocol.oversee(make_action())
        self.assertTrue(report.spot_checked)

    def test_spot_check_only_on_approval(self):
        protocol = make_protocol(spot_check_rate=1.0)
        report = protocol.oversee(make_action(tier=RiskTier.CRITICAL, confidence=1.0))
        self.assertEqual(report.verdict, Verdict.DENIED)
        self.assertFalse(report.spot_checked)


class TestEscalateAndReview(unittest.TestCase):
    def test_escalate_routes_to_escalation_method(self):
        protocol = make_protocol(escalation_method=OversightMethod.AMPLIFICATION)
        routed = protocol.escalate(make_action(tier=RiskTier.HIGH, confidence=0.3))
        self.assertEqual(routed.verdict, Verdict.NEEDS_REVIEW)
        self.assertEqual(routed.method_used, OversightMethod.AMPLIFICATION)

    def test_review_supporting_evidence_approves(self):
        protocol = make_protocol(threshold=0.5)
        evidence = StrongEvidence(OversightMethod.DEBATE, True, 0.8)
        report = protocol.review(make_action(tier=RiskTier.HIGH), evidence)
        self.assertEqual(report.verdict, Verdict.APPROVED)
        self.assertEqual(report.method_used, OversightMethod.DEBATE)

    def test_review_opposing_evidence_denies(self):
        protocol = make_protocol(threshold=0.5)
        evidence = StrongEvidence(OversightMethod.DEBATE, False, 0.9)
        report = protocol.review(make_action(tier=RiskTier.HIGH), evidence)
        self.assertEqual(report.verdict, Verdict.DENIED)

    def test_review_weak_support_denies(self):
        protocol = make_protocol(threshold=0.5)
        evidence = StrongEvidence(OversightMethod.CONSTITUTIONAL, True, 0.3)
        report = protocol.review(make_action(tier=RiskTier.HIGH), evidence)
        self.assertEqual(report.verdict, Verdict.DENIED)

    def test_evidence_confidence_validation(self):
        with self.assertRaises(ValueError):
            StrongEvidence(OversightMethod.DEBATE, True, 1.5)
        with self.assertRaises(TypeError):
            StrongEvidence(OversightMethod.DEBATE, "yes", 0.8)


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        report = make_protocol().oversee(make_action())
        event = oversight_audit_event(report, 7)
        self.assertEqual(event["event"], "oversight-decision")
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["verdict"], "approved")
        self.assertEqual(event["schema"], SCHEMA_PIN)

    def test_audit_event_bad_seq(self):
        report = make_protocol().oversee(make_action())
        with self.assertRaises(ValueError):
            oversight_audit_event(report, -1)


if __name__ == "__main__":
    unittest.main()
