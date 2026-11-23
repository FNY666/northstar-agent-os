"""Tests for the spec API surface of scalable_oversight.py (batch-46 additive).

Covers ScalableOversight / delegate() / audit() as additive aliases of the
batch-7 OversightProtocol / escalate() / oversight_audit_event(); all 31
pre-existing tests in test_scalable_oversight.py must keep passing unchanged.
"""

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
    ScalableOversight,
    StrongEvidence,
    Verdict,
    oversight_audit_event,
)


def make_spec(**kwargs):
    defaults = dict(method=OversightMethod.DIRECT, threshold=0.5)
    defaults.update(kwargs)
    return ScalableOversight(**defaults)


def make_action(action_id="s1", action_type="newsletter.send",
                tier=RiskTier.LOW, confidence=0.95):
    return OverseenAction(action_id, action_type, tier, confidence)


class TestSpecClass(unittest.TestCase):
    def test_is_subclass_of_protocol(self):
        self.assertTrue(issubclass(ScalableOversight, OversightProtocol))

    def test_instance_is_protocol(self):
        self.assertIsInstance(make_spec(), OversightProtocol)

    def test_version_pin(self):
        self.assertEqual(SCALABLE_OVERSIGHT_VERSION, "scalable-oversight.v1")

    def test_frozen(self):
        spec = make_spec()
        with self.assertRaises(FrozenInstanceError):
            spec.threshold = 0.9

    def test_constructor_validation_inherited(self):
        with self.assertRaises(ValueError):
            make_spec(threshold=1.5)
        with self.assertRaises(TypeError):
            make_spec(deny_above="CRITICAL")


class TestSpecOversee(unittest.TestCase):
    def test_oversee_approve(self):
        report = make_spec().oversee(make_action())
        self.assertIsInstance(report, OversightReport)
        self.assertEqual(report.verdict, Verdict.APPROVED)

    def test_oversee_deny(self):
        report = make_spec().oversee(make_action(tier=RiskTier.CRITICAL))
        self.assertEqual(report.verdict, Verdict.DENIED)

    def test_oversee_needs_review(self):
        report = make_spec().oversee(make_action(tier=RiskTier.HIGH, confidence=0.4))
        self.assertEqual(report.verdict, Verdict.NEEDS_REVIEW)

    def test_oversee_rejects_non_action(self):
        with self.assertRaises(TypeError):
            make_spec().oversee("not an action")


class TestSpecDelegate(unittest.TestCase):
    def test_delegate_routes_to_escalation_method(self):
        spec = make_spec(escalation_method=OversightMethod.CONSTITUTIONAL)
        routed = spec.delegate(make_action(tier=RiskTier.HIGH, confidence=0.3))
        self.assertEqual(routed.verdict, Verdict.NEEDS_REVIEW)
        self.assertEqual(routed.method_used, OversightMethod.CONSTITUTIONAL)
        self.assertEqual(routed.action_id, "s1")

    def test_delegate_matches_escalate(self):
        spec = make_spec()
        action = make_action(tier=RiskTier.MEDIUM, confidence=0.4)
        via_delegate = spec.delegate(action)
        via_escalate = spec.escalate(action)
        self.assertEqual(via_delegate.as_dict(), via_escalate.as_dict())

    def test_delegate_rejects_non_action(self):
        with self.assertRaises(TypeError):
            make_spec().delegate(None)


class TestSpecAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        spec = make_spec()
        report = spec.oversee(make_action())
        event = spec.audit(report, 11)
        self.assertEqual(event["event"], "oversight-decision")
        self.assertEqual(event["audit_seq"], 11)
        self.assertEqual(event["verdict"], "approved")
        self.assertEqual(event["schema"], SCHEMA_PIN)

    def test_audit_matches_function(self):
        spec = make_spec()
        report = spec.oversee(make_action())
        self.assertEqual(spec.audit(report, 5), oversight_audit_event(report, 5))

    def test_audit_bad_seq(self):
        spec = make_spec()
        report = spec.oversee(make_action())
        with self.assertRaises(ValueError):
            spec.audit(report, -1)
        with self.assertRaises(TypeError):
            spec.audit(report, True)

    def test_audit_bad_report(self):
        with self.assertRaises(TypeError):
            make_spec().audit("not a report", 1)


class TestSpecWorkflow(unittest.TestCase):
    def test_delegate_review_roundtrip(self):
        spec = make_spec(threshold=0.5, escalation_method=OversightMethod.DEBATE)
        action = make_action(tier=RiskTier.HIGH, confidence=0.4)
        routed = spec.delegate(action)
        final = spec.review(action, StrongEvidence(OversightMethod.DEBATE, True, 0.8))
        self.assertEqual(routed.verdict, Verdict.NEEDS_REVIEW)
        self.assertEqual(final.verdict, Verdict.APPROVED)


if __name__ == "__main__":
    unittest.main()
