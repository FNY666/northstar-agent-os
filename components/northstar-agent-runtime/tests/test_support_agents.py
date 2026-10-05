"""Tests for support_agents.py (one-hundred-fifty-sixth batch)."""

from __future__ import annotations

import unittest

import ed25519

import support_agents as sa


T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
HEX64_C = "ef" * 32


def _keypair(seed: int):
    secret = bytes([seed]) * 32
    return secret, ed25519.public_key(secret)


SEC, PUB = _keypair(7)


class _Base(unittest.TestCase):
    def identity_receipt(self, **kw):
        args = dict(
            receipt_id="idr-1",
            session_id="sess-1",
            agent_id="agent-voice-1",
            agent_kind="ai_voice",
            disclosed_at=T0,
            disclosure_text_digest=HEX64,
            channel="voice",
            issuer_secret=SEC,
            issuer_pubkey=PUB,
        )
        args.update(kw)
        return sa.issue_identity_receipt(**args)

    def handoff(self, **kw):
        args = dict(
            receipt_id="hop-1",
            session_id="sess-1",
            requested_at=T0,
            hopped_at=T0 + 45,
            from_agent_id="agent-voice-1",
            to_agent_id="human-7",
            previous_digest="00" * 32,
            issuer_secret=SEC,
            issuer_pubkey=PUB,
        )
        args.update(kw)
        return sa.issue_handoff_receipt(**args)

    def claim(self, **kw):
        args = dict(
            claim_id="cl-1",
            session_id="sess-1",
            claim_category="fee",
            claim_text_digest=HEX64,
            kb_evidence_digest=HEX64_B,
            issued_at=T0,
            expires_at=T0 + 86400,
            issuer_secret=SEC,
            issuer_pubkey=PUB,
        )
        args.update(kw)
        return sa.issue_claim_receipt(**args)

    def registry(self):
        reg = sa.WorkforceRegistry()
        reg.register(
            agent_id="agent-voice-1", agent_kind="ai_voice",
            claimed_kind="ai_voice", registered_at=T0, operator_id="op-1",
            issuer_secret=SEC, issuer_pubkey=PUB,
        )
        return reg

    def budget(self, **kw):
        args = dict(
            budget_id="bud-1",
            workforce_agent_id="agent-voice-1",
            purpose="quality_assurance",
            scope="call-audio",
            retention_days=90,
            issued_at=T0,
            expires_at=T0 + 86400 * 90,
            issuer_secret=SEC,
            issuer_pubkey=PUB,
        )
        args.update(kw)
        return sa.issue_collection_budget(**args)

    def probe(self, **kw):
        args = dict(
            probe_id="qp-1",
            org_id="org-1",
            period_start=T0,
            period_end=T0 + 86400 * 30,
            ai_resolution_rate_bps=6500,
            csat_delta_bps=-1500,
            escalation_delta_bps=2000,
            layoff_event_digest=HEX64,
        )
        args.update(kw)
        return sa.issue_quality_probe(**args)


class TestIdentityDisclosure(_Base):
    def test_disclosed_session_allows(self):
        session = sa.Session(session_id="sess-1", agent_id="agent-voice-1", started_at=T0)
        v = sa.check_identity_disclosure(session, self.identity_receipt())
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_no_receipt_denies_undisclosed(self):
        session = sa.Session(session_id="sess-1", agent_id="agent-voice-1", started_at=T0)
        v = sa.check_identity_disclosure(session, None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_UNDISCLOSED_AI)

    def test_late_disclosure_denies(self):
        session = sa.Session(session_id="sess-1", agent_id="agent-voice-1", started_at=T0)
        r = self.identity_receipt(disclosed_at=T0 + sa.DISCLOSURE_GRACE_SECONDS + 1)
        v = sa.check_identity_disclosure(session, r)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_UNDISCLOSED_AI)

    def test_tampered_disclosure_signature_denies(self):
        session = sa.Session(session_id="sess-1", agent_id="agent-voice-1", started_at=T0)
        r = self.identity_receipt()
        bad = sa.IdentityReceipt(**{**r.__dict__, "signature_hex": "ff" * 64})
        v = sa.check_identity_disclosure(session, bad)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_UNDISCLOSED_AI)

    def test_ai_disclosing_as_human_refused_at_issuance(self):
        with self.assertRaises(sa.SupportError):
            self.identity_receipt(agent_kind="human")


class TestHumanEscapeClock(_Base):
    def test_timely_handoff_allows(self):
        v = sa.human_escape_clock(
            session_id="sess-1", requested_at=T0, now=T0 + 60,
            hops=(self.handoff(),), max_wait_seconds=300,
            human_agent_ids=frozenset({"human-7"}),
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_handoff_timeout_denies(self):
        v = sa.human_escape_clock(
            session_id="sess-1", requested_at=T0, now=T0 + 900,
            hops=(), max_wait_seconds=300,
            human_agent_ids=frozenset({"human-7"}),
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_NO_HUMAN_ESCAPE)

    def test_handoff_loop_denies(self):
        hop = self.handoff()
        v = sa.human_escape_clock(
            session_id="sess-1", requested_at=T0, now=T0 + 60,
            hops=(hop, hop), max_wait_seconds=300,
            human_agent_ids=frozenset({"human-7"}),
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_NO_HUMAN_ESCAPE)

    def test_self_hop_refused_at_issuance(self):
        with self.assertRaises(sa.SupportError):
            self.handoff(from_agent_id="x", to_agent_id="x")


class TestClaimReceipts(_Base):
    def test_evidenced_claim_authoritative(self):
        v = sa.adversarial_claim_receipt(
            self.claim(), kb_live_digests=frozenset({HEX64_B}), now=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_dead_evidence_non_authoritative(self):
        v = sa.adversarial_claim_receipt(
            self.claim(), kb_live_digests=frozenset({HEX64_C}), now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.tier, sa.NON_AUTHORITATIVE)
        self.assertEqual(v.deny_code, sa.DENY_UNEVIDENCED_CLAIM)

    def test_empty_evidence_refused_at_issuance(self):
        with self.assertRaises(sa.SupportError):
            self.claim(kb_evidence_digest="00" * 32)


class TestWorkforceRegistry(_Base):
    def test_registered_matching_kind_allows(self):
        v = sa.agent_workforce_registry(
            self.registry(), agent_id="agent-voice-1", presented_kind="ai_voice")
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_unregistered_agent_denies(self):
        v = sa.agent_workforce_registry(
            self.registry(), agent_id="ghost", presented_kind="ai_voice")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_UNREGISTERED_AGENT)

    def test_ai_posing_as_human_is_fraud(self):
        v = sa.agent_workforce_registry(
            self.registry(), agent_id="agent-voice-1", presented_kind="human")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_IDENTITY_FRAUD)

    def test_duplicate_registration_refused(self):
        reg = self.registry()
        with self.assertRaises(sa.SupportError):
            reg.register(
                agent_id="agent-voice-1", agent_kind="ai_voice",
                claimed_kind="ai_voice", registered_at=T0, operator_id="op-1",
                issuer_secret=SEC, issuer_pubkey=PUB,
            )


class TestSurveillanceBudget(_Base):
    def test_in_budget_collection_allows(self):
        v = sa.surveillance_budget(
            self.budget(), actual_purpose="quality_assurance",
            training_replacement_model=False, now=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_replacement_training_is_overreach(self):
        v = sa.surveillance_budget(
            self.budget(), actual_purpose="quality_assurance",
            training_replacement_model=True, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_SURVEILLANCE_OVERREACH)

    def test_wrong_purpose_is_overreach(self):
        v = sa.surveillance_budget(
            self.budget(), actual_purpose="coaching",
            training_replacement_model=False, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_SURVEILLANCE_OVERREACH)

    def test_replacement_purpose_refused_at_issuance(self):
        with self.assertRaises(sa.SupportError):
            self.budget(purpose="train_replacement_model")


class TestEmotionInferenceBan(_Base):
    def test_emotion_inference_refused_whole_class(self):
        for purpose in ("emotion_inference", "sentiment_scoring", "mood_detection"):
            v = sa.emotion_inference_ban(purpose=purpose)
            self.assertFalse(v.allowed, purpose)
            self.assertEqual(v.deny_code, sa.DENY_EMOTION_INFERENCE)

    def test_legitimate_purpose_allows(self):
        v = sa.emotion_inference_ban(purpose="quality_assurance")
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)


class TestRehireProbe(_Base):
    def test_post_layoff_collapse_triggers_rehire_probe(self):
        v = sa.rehire_probe(self.probe(), csat_drop_threshold_bps=1000,
                            escalation_rise_threshold_bps=1000)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_OVER_AUTOMATION)

    def test_no_layoff_no_verdict(self):
        v = sa.rehire_probe(self.probe(layoff_event_digest="00" * 32),
                            csat_drop_threshold_bps=1000,
                            escalation_rise_threshold_bps=1000)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_post_layoff_within_tolerance_allows(self):
        v = sa.rehire_probe(self.probe(csat_delta_bps=-200, escalation_delta_bps=100),
                            csat_drop_threshold_bps=1000,
                            escalation_rise_threshold_bps=1000)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)


class TestFloodCircuit(_Base):
    def test_normal_arrivals_no_flood(self):
        p = sa.issue_flood_probe(probe_id="fp-1", queue_id="q-1",
                                 window_start=T0, window_end=T0 + 3600,
                                 total_arrivals=1200,
                                 consumer_agent_arrivals=200,
                                 capacity_per_window=1000)
        v = sa.agent_flood_circuit(p, flood_multiple=100)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, sa.AUTHORITATIVE)

    def test_consumer_agent_flood_trips_breaker(self):
        p = sa.issue_flood_probe(probe_id="fp-2", queue_id="q-1",
                                 window_start=T0, window_end=T0 + 3600,
                                 total_arrivals=100_000,
                                 consumer_agent_arrivals=100_000,
                                 capacity_per_window=1000)
        v = sa.agent_flood_circuit(p, flood_multiple=100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, sa.DENY_AGENT_FLOOD)


if __name__ == "__main__":
    unittest.main()
