"""Tests for booking_agents.py (one-hundred-twenty-third batch)."""

import unittest

from booking_agents import (
    DENY_CEILING_BREACH,
    DENY_CONTEXT_BROKEN,
    DENY_HIDDEN_COMMERCIAL_BIAS,
    DENY_NO_INTENT,
    DENY_POLICY_DRIFT,
    DENY_STALE_ASSERTION,
    DENY_UNDISCLOSED_PRICING,
    DENY_UNKNOWN_ASSERTION,
    DENY_UNVERIFIABLE_DENIAL,
    AuthorityRegistry,
    BookingError,
    BookingSession,
    FreshnessRegistry,
    RebookingLog,
    authorize_transaction,
    commercial_bias_gate,
    issue_intent,
    issue_policy,
    issue_pricing_disclosure,
    issue_recommendation_disclosure,
    policy_consistency_gate,
    pricing_disclosure_gate,
)
from ed25519 import public_key as ed_public_key

T0 = 1_700_000_000
AUTH_SECRET = bytes([9]) * 32
AUTH_PUB = ed_public_key(AUTH_SECRET)
MERCHANT_SECRET = bytes([11]) * 32
MERCHANT_PUB = ed_public_key(MERCHANT_SECRET)
REGISTRY = AuthorityRegistry(
    {"platform": AUTH_PUB, "merchant": MERCHANT_PUB}
)
ROUTE = "ab" * 32
PAYLOAD = "cd" * 32


def make_intent(**over):
    kw = dict(
        registry=REGISTRY,
        authority_secret=AUTH_SECRET,
        receipt_id="intent-1",
        agent_id="booking-agent",
        traveler_id="traveler-1",
        route_or_stay_digest=ROUTE,
        purpose="leisure_travel",
        price_ceiling_minor_units=50000,
        currency="USD",
        issued_by="platform",
        issued_at=T0,
        expires_at=T0 + 86_400,
    )
    kw.update(over)
    return issue_intent(**kw)


class TestIntentCeiling(unittest.TestCase):
    def test_within_ceiling_allows(self):
        intent = make_intent()
        v = authorize_transaction(
            REGISTRY,
            [intent],
            agent_id="booking-agent",
            traveler_id="traveler-1",
            route_or_stay_digest=ROUTE,
            total_minor_units=40000,
            currency="USD",
            check_time=T0 + 10,
        )
        self.assertTrue(v.allowed)

    def test_ceiling_breach_denies(self):
        intent = make_intent()
        v = authorize_transaction(
            REGISTRY,
            [intent],
            agent_id="booking-agent",
            traveler_id="traveler-1",
            route_or_stay_digest=ROUTE,
            total_minor_units=60000,
            currency="USD",
            check_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_CEILING_BREACH, v.reason)

    def test_no_matching_intent_denies(self):
        v = authorize_transaction(
            REGISTRY,
            [],
            agent_id="booking-agent",
            traveler_id="traveler-1",
            route_or_stay_digest=ROUTE,
            total_minor_units=100,
            currency="USD",
            check_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_NO_INTENT, v.reason)

    def test_expired_intent_denies(self):
        intent = make_intent()
        v = authorize_transaction(
            REGISTRY,
            [intent],
            agent_id="booking-agent",
            traveler_id="traveler-1",
            route_or_stay_digest=ROUTE,
            total_minor_units=100,
            currency="USD",
            check_time=T0 + 100_000,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_NO_INTENT, v.reason)

    def test_self_issued_intent_rejected(self):
        with self.assertRaises(BookingError):
            make_intent(agent_id="platform", issued_by="platform")


class TestFreshness(unittest.TestCase):
    def test_fresh_assertion_allows(self):
        reg = FreshnessRegistry()
        a = reg.register(
            assertion_id="a1",
            kind="price",
            payload_digest=PAYLOAD,
            observed_at=T0,
            ttl_seconds=3600,
        )
        v = reg.check_freshness(
            assertion_id="a1",
            kind="price",
            payload_digest=PAYLOAD,
            use_time=T0 + 100,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.receipt_digest, a.receipt_digest)

    def test_stale_assertion_denies_non_authoritative(self):
        reg = FreshnessRegistry()
        reg.register(
            assertion_id="a1",
            kind="price",
            payload_digest=PAYLOAD,
            observed_at=T0,
            ttl_seconds=3600,
        )
        v = reg.check_freshness(
            assertion_id="a1",
            kind="price",
            payload_digest=PAYLOAD,
            use_time=T0 + 7200,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_STALE_ASSERTION, v.reason)
        self.assertEqual(v.classification, "non_authoritative")

    def test_unknown_assertion_denies(self):
        reg = FreshnessRegistry()
        v = reg.check_freshness(
            assertion_id="nope",
            kind="price",
            payload_digest=PAYLOAD,
            use_time=T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNKNOWN_ASSERTION, v.reason)

    def test_mismatched_payload_denies(self):
        reg = FreshnessRegistry()
        reg.register(
            assertion_id="a1",
            kind="price",
            payload_digest=PAYLOAD,
            observed_at=T0,
            ttl_seconds=3600,
        )
        v = reg.check_freshness(
            assertion_id="a1",
            kind="price",
            payload_digest="ee" * 32,
            use_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNKNOWN_ASSERTION, v.reason)


class TestPricingDisclosure(unittest.TestCase):
    def test_fixed_pricing_needs_no_disclosure(self):
        v = pricing_disclosure_gate(
            REGISTRY, [], quote_digest=PAYLOAD, pricing_kind="fixed"
        )
        self.assertTrue(v.allowed)

    def test_dynamic_with_disclosure_allows(self):
        d = issue_pricing_disclosure(
            REGISTRY,
            MERCHANT_SECRET,
            receipt_id="disc-1",
            quote_digest=PAYLOAD,
            pricing_kind="dynamic",
            disclosure_digest="fa" * 32,
            issued_by="merchant",
            issued_at=T0,
        )
        v = pricing_disclosure_gate(
            REGISTRY, [d], quote_digest=PAYLOAD, pricing_kind="dynamic"
        )
        self.assertTrue(v.allowed)

    def test_personalized_without_disclosure_denies(self):
        v = pricing_disclosure_gate(
            REGISTRY, [], quote_digest=PAYLOAD, pricing_kind="personalized"
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNDISCLOSED_PRICING, v.reason)

    def test_disclosure_for_wrong_quote_denies(self):
        d = issue_pricing_disclosure(
            REGISTRY,
            MERCHANT_SECRET,
            receipt_id="disc-1",
            quote_digest="ee" * 32,
            pricing_kind="dynamic",
            disclosure_digest="fa" * 32,
            issued_by="merchant",
            issued_at=T0,
        )
        v = pricing_disclosure_gate(
            REGISTRY, [d], quote_digest=PAYLOAD, pricing_kind="dynamic"
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNDISCLOSED_PRICING, v.reason)


class TestPolicyConsistency(unittest.TestCase):
    def test_matching_policy_allows(self):
        p = issue_policy(
            REGISTRY,
            AUTH_SECRET,
            receipt_id="pol-1",
            policy_digest=PAYLOAD,
            issued_by="platform",
            issued_at=T0,
        )
        v = policy_consistency_gate(
            REGISTRY, [p], output_policy_digest=PAYLOAD, check_time=T0 + 10
        )
        self.assertTrue(v.allowed)

    def test_drift_denies_with_human_review(self):
        p = issue_policy(
            REGISTRY,
            AUTH_SECRET,
            receipt_id="pol-1",
            policy_digest=PAYLOAD,
            issued_by="platform",
            issued_at=T0,
        )
        v = policy_consistency_gate(
            REGISTRY,
            [p],
            output_policy_digest="ee" * 32,
            check_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_POLICY_DRIFT, v.reason)
        self.assertTrue(v.mandatory_human_review)


class TestOverbookingPreemption(unittest.TestCase):
    def test_preemption_before_denial_allows(self):
        log = RebookingLog()
        log.append(
            receipt_id="rb-1",
            passenger_id="pax-1",
            flight_digest=ROUTE,
            new_flight_digest=PAYLOAD,
            reason="overbooked",
            created_at=T0,
        )
        v = log.deny_boarding_gate(
            passenger_id="pax-1", flight_digest=ROUTE, denial_time=T0 + 100
        )
        self.assertTrue(v.allowed)

    def test_no_preemption_denies(self):
        log = RebookingLog()
        v = log.deny_boarding_gate(
            passenger_id="pax-1", flight_digest=ROUTE, denial_time=T0 + 100
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNVERIFIABLE_DENIAL, v.reason)

    def test_preemption_after_denial_denies(self):
        log = RebookingLog()
        log.append(
            receipt_id="rb-1",
            passenger_id="pax-1",
            flight_digest=ROUTE,
            new_flight_digest=PAYLOAD,
            reason="overbooked",
            created_at=T0 + 200,
        )
        v = log.deny_boarding_gate(
            passenger_id="pax-1", flight_digest=ROUTE, denial_time=T0 + 100
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNVERIFIABLE_DENIAL, v.reason)


class TestContextContinuity(unittest.TestCase):
    def test_continuous_session_allows(self):
        s = BookingSession(
            session_id="s1", agent_id="agent", traveler_id="traveler-1"
        )
        s.append_turn(turn_digest=PAYLOAD, started_at=T0)
        v = s.context_continuity_probe(check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_broken_session_denies(self):
        s = BookingSession(
            session_id="s1", agent_id="agent", traveler_id="traveler-1"
        )
        s.append_turn(turn_digest=PAYLOAD, started_at=T0)
        s.mark_context_lost()
        v = s.context_continuity_probe(check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_CONTEXT_BROKEN, v.reason)

    def test_append_after_break_raises(self):
        s = BookingSession(
            session_id="s1", agent_id="agent", traveler_id="traveler-1"
        )
        s.mark_context_lost()
        with self.assertRaises(BookingError):
            s.append_turn(turn_digest=PAYLOAD, started_at=T0)


class TestCommercialBias(unittest.TestCase):
    def test_no_paid_placement_needs_no_disclosure(self):
        v = commercial_bias_gate(
            REGISTRY,
            [],
            recommendation_digest=PAYLOAD,
            paid_placement=False,
        )
        self.assertTrue(v.allowed)

    def test_disclosed_paid_placement_allows(self):
        d = issue_recommendation_disclosure(
            REGISTRY,
            MERCHANT_SECRET,
            receipt_id="rec-1",
            recommendation_digest=PAYLOAD,
            paid_placement=True,
            disclosure_digest="fa" * 32,
            issued_by="merchant",
            issued_at=T0,
        )
        v = commercial_bias_gate(
            REGISTRY,
            [d],
            recommendation_digest=PAYLOAD,
            paid_placement=True,
        )
        self.assertTrue(v.allowed)

    def test_undisclosed_paid_placement_denies(self):
        v = commercial_bias_gate(
            REGISTRY,
            [],
            recommendation_digest=PAYLOAD,
            paid_placement=True,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_HIDDEN_COMMERCIAL_BIAS, v.reason)


if __name__ == "__main__":
    unittest.main()
