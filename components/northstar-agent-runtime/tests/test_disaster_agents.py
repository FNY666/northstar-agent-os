"""Tests for disaster_agents.py (one-hundred-thirty-seventh batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

import ed25519
from ed25519 import public_key

from disaster_agents import (
    DISASTER_SCHEMA_VERSION,
    EQUITY_FRESHNESS_S,
    AlarmBudgetReceipt,
    AlarmBudgetRegistry,
    DeliveryReceipt,
    DeliveryRegistry,
    DisasterError,
    DisasterVerdict,
    DisclosureReceipt,
    DisclosureRegistry,
    EquityReceipt,
    EvacuationOrder,
    TriageActivationReceipt,
    TriageRegistry,
    WarningVersion,
    WarningVersionChain,
    ai_involvement_disclosure,
    check_evacuation_order,
    equity_probe,
    equity_receipt,
    false_alarm_budget,
    human_final_decision,
    last_mile_receipt,
    misinfo_marker_probe,
    triage_activation_receipt,
    warning_version,
)

T0 = 1_700_000_000
SEED = bytes(range(32))
AUTH_PUB = public_key(SEED).hex()
HUMAN_SEED = bytes(range(32, 64))
HUMAN_PUB = public_key(HUMAN_SEED).hex()
D1 = "ab" * 32
D2 = "cd" * 32
D3 = "ef" * 32


def _triage(deployment="dep-1", channel="voice_911", issued=T0, ttl=3600):
    return triage_activation_receipt(
        receipt_id="t-1",
        deployment_id=deployment,
        channel=channel,
        activation_digest=D1,
        issued_at=issued,
        ttl_s=ttl,
        issued_by="psap-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
    )


def _disclosure(session="s-1", at=T0, ttl=3600):
    return ai_involvement_disclosure(
        receipt_id="d-1",
        session_id=session,
        deployment_id="dep-1",
        modality="triage_routing",
        disclosed_at=at,
        ttl_s=ttl,
        issued_by="psap-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
    )


def _warning_v(version, warning="w-1", at=T0, prev="genesis", digest=None):
    return warning_version(
        version_id="v-%d" % version,
        warning_id=warning,
        version=version,
        content_digest=digest or D1,
        issued_at=at,
        issued_by="warning-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
        prev_digest=prev,
    )


def _budget(channel="cell_broadcast", max_bps=500, window=86400):
    return false_alarm_budget(
        receipt_id="b-1",
        channel_id=channel,
        max_false_alarm_bps=max_bps,
        window_s=window,
        issued_at=T0,
        issued_by="warning-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
    )


def _equity(coverage=8500, minimum=7000, measured=T0):
    return equity_receipt(
        receipt_id="e-1",
        deployment_id="dep-1",
        coverage_bps=coverage,
        min_required_bps=minimum,
        measured_at=measured,
        protocol_digest=D2,
        issued_by="equity-audit",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
    )


def _delivery(version_digest=None):
    return last_mile_receipt(
        receipt_id="l-1",
        warning_version_digest=version_digest or D1,
        delivery_proof_digest=D3,
        delivered_at=T0,
        reach_count=12000,
        channel_id="cell_broadcast",
        issued_by="carrier-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
    )


def _order():
    return human_final_decision(
        order_id="o-1",
        order_digest=D1,
        zone="zone-7",
        issued_at=T0,
        expires_at=T0 + 7200,
        issued_by="emergency-ops",
        human_signer="incident-commander",
        human_pubkey_hex=HUMAN_PUB,
        human_secret=HUMAN_SEED,
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=SEED,
    )


def _marker_notice():
    from disaster_agents import _marker_payload
    from canonical_json import jcs_canonical_json, jcs_sha256_hex

    payload = _marker_payload(
        notice_digest=D1,
        originator="county-ema",
        channel="cell_broadcast",
        created_unix=T0,
    )
    sig = ed25519.sign(SEED, jcs_canonical_json(payload)).hex()
    return {
        "notice_id": "n-1",
        "originator": "county-ema",
        "channel": "cell_broadcast",
        "created_unix": T0,
        "notice_digest": D1,
        "source_marker": {
            "digest": jcs_sha256_hex(payload),
            "pubkey_hex": AUTH_PUB,
            "signature_hex": sig,
        },
    }


class TestTriageActivation(unittest.TestCase):
    def test_allow_live_activation(self):
        reg = TriageRegistry()
        reg.register(_triage())
        v = reg.check_activation(deployment_id="dep-1", channel="voice_911", now=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "allow")

    def test_deny_unbound(self):
        reg = TriageRegistry()
        v = reg.check_activation(deployment_id="ghost", channel="voice_911", now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("unauthorized_triage", v.reason)

    def test_deny_expired(self):
        reg = TriageRegistry()
        reg.register(_triage(ttl=100))
        v = reg.check_activation(deployment_id="dep-1", channel="voice_911", now=T0 + 200)
        self.assertFalse(v.allowed)
        self.assertIn("unauthorized_triage", v.reason)

    def test_deny_revoked(self):
        reg = TriageRegistry()
        reg.register(_triage())
        reg.revoke("dep-1")
        v = reg.check_activation(deployment_id="dep-1", channel="voice_911", now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("revoked", v.reason)

    def test_chain_break_raises(self):
        reg = TriageRegistry()
        reg.register(_triage())
        with self.assertRaises(DisasterError):
            reg.register(_triage())  # same genesis prev twice breaks the chain

    def test_bad_channel_rejected(self):
        with self.assertRaises(DisasterError):
            _triage(channel="pigeon")


class TestDisclosure(unittest.TestCase):
    def test_allow_disclosed(self):
        reg = DisclosureRegistry()
        reg.register(_disclosure())
        v = reg.check_disclosure(session_id="s-1", now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_hidden(self):
        reg = DisclosureRegistry()
        v = reg.check_disclosure(session_id="s-9", now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("hidden_ai", v.reason)

    def test_deny_expired_disclosure(self):
        reg = DisclosureRegistry()
        reg.register(_disclosure(ttl=100))
        v = reg.check_disclosure(session_id="s-1", now=T0 + 200)
        self.assertFalse(v.allowed)
        self.assertIn("hidden_ai", v.reason)


class TestWarningVersionChain(unittest.TestCase):
    def test_allow_head_reference(self):
        chain = WarningVersionChain()
        v1 = chain.publish(_warning_v(1))
        chain.publish(_warning_v(2, at=T0 + 60, prev=v1.receipt_digest))
        v = chain.check_reference(
            version_digest=chain._heads["w-1"].receipt_digest, now=T0 + 100
        )
        self.assertTrue(v.allowed)

    def test_superseded_is_non_authoritative(self):
        chain = WarningVersionChain()
        v1 = chain.publish(_warning_v(1))
        chain.publish(_warning_v(2, at=T0 + 60, prev=v1.receipt_digest))
        v = chain.check_reference(version_digest=v1.receipt_digest, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")
        self.assertIn("superseded_warning", v.reason)

    def test_unknown_digest_denied(self):
        chain = WarningVersionChain()
        chain.publish(_warning_v(1))
        v = chain.check_reference(version_digest=D3, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("unknown_warning_version", v.reason)

    def test_version_must_increase(self):
        chain = WarningVersionChain()
        v1 = chain.publish(_warning_v(1))
        with self.assertRaises(DisasterError):
            chain.publish(_warning_v(1, at=T0 + 60, prev=v1.receipt_digest))


class TestAlarmBudget(unittest.TestCase):
    def test_allow_within_budget(self):
        reg = AlarmBudgetRegistry()
        reg.register(_budget())
        v = reg.check_rate(
            channel_id="cell_broadcast", observed_false_alarm_bps=100, now=T0
        )
        self.assertTrue(v.allowed)

    def test_over_budget_degrades(self):
        reg = AlarmBudgetRegistry()
        reg.register(_budget(max_bps=500))
        v = reg.check_rate(
            channel_id="cell_broadcast", observed_false_alarm_bps=900, now=T0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")
        self.assertIn("false_alarm_budget_exceeded", v.reason)

    def test_no_budget_fails_closed(self):
        reg = AlarmBudgetRegistry()
        v = reg.check_rate(
            channel_id="cell_broadcast", observed_false_alarm_bps=0, now=T0
        )
        self.assertFalse(v.allowed)
        self.assertIn("no_alarm_budget", v.reason)


class TestEquityProbe(unittest.TestCase):
    def test_allow_adequate(self):
        v = equity_probe(_equity(), now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_gap(self):
        v = equity_probe(_equity(coverage=4000, minimum=7000), now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("equity_gap", v.reason)

    def test_deny_stale(self):
        v = equity_probe(_equity(measured=T0), now=T0 + EQUITY_FRESHNESS_S + 1)
        self.assertFalse(v.allowed)
        self.assertIn("stale_equity_measurement", v.reason)

    def test_tampered_digest_fails(self):
        r = _equity()
        bad = EquityReceipt(**{**r.__dict__, "receipt_digest": "00" * 32})
        v = equity_probe(bad, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("digest_mismatch", v.reason)


class TestDelivery(unittest.TestCase):
    def test_allow_bound_delivery(self):
        reg = DeliveryRegistry()
        reg.register(_delivery())
        v = reg.check_authority(warning_version_digest=D1, now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_unbound_is_non_authoritative(self):
        reg = DeliveryRegistry()
        v = reg.check_authority(warning_version_digest=D2, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")
        self.assertIn("no_delivery_evidence", v.reason)


class TestEvacuationOrder(unittest.TestCase):
    def test_allow_human_signed(self):
        v = check_evacuation_order(_order(), now=T0 + 100)
        self.assertTrue(v.allowed)
        self.assertIn("incident-commander", v.audit_event.get("human_signer", ""))

    def test_deny_expired(self):
        v = check_evacuation_order(_order(), now=T0 + 8000)
        self.assertFalse(v.allowed)
        self.assertIn("order_expired", v.reason)

    def test_ai_only_order_denied(self):
        from disaster_agents import _seal_receipt

        order = _order()
        bare = EvacuationOrder(**{**order.__dict__, "human_signature_hex": ""})
        # re-seal so the authority form still verifies but no countersign exists
        digest, sig = _seal_receipt(bare._payload(), SEED)
        bare = EvacuationOrder(
            **{**bare.__dict__, "signature_hex": sig, "receipt_digest": digest}
        )
        v = check_evacuation_order(bare, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("ai_evacuation", v.reason)


class TestMarkerProbe(unittest.TestCase):
    def test_allow_marked(self):
        v = misinfo_marker_probe(_marker_notice())
        self.assertTrue(v.allowed)

    def test_deny_unmarked(self):
        n = _marker_notice()
        del n["source_marker"]
        v = misinfo_marker_probe(n)
        self.assertFalse(v.allowed)
        self.assertIn("unmarked_notice", v.reason)

    def test_deny_mismatch(self):
        n = _marker_notice()
        n["source_marker"] = {**n["source_marker"], "digest": "ff" * 32}
        v = misinfo_marker_probe(n)
        self.assertFalse(v.allowed)
        self.assertIn("marker_mismatch", v.reason)

    def test_malformed_raises(self):
        with self.assertRaises(DisasterError):
            misinfo_marker_probe({"notice_id": "x"})


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version(self):
        self.assertEqual(DISASTER_SCHEMA_VERSION, "northstar.disaster-agents.v1")


if __name__ == "__main__":
    unittest.main()
