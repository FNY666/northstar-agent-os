"""Tests for greenwash.py (one-hundred-thirtieth batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

import ed25519

from greenwash import (
    ATTRIBUTION_METHODS,
    GREENWASH_SCHEMA_VERSION,
    PURITY_TOLERANCE_BPS,
    BatteryInspectionLog,
    ClaimEvidenceLog,
    DecommissionLog,
    GreenwashError,
    PurityClaimLog,
    RecycledContentLog,
    battery_inspection_receipt,
    battery_second_life_gate,
    claim_evidence_chain,
    claim_evidence_receipt,
    decommission_path,
    decommission_receipt,
    greenwash_audit_event,
    greenwash_probe,
    mass_balance_method_gate,
    purity_claim_binding,
    check_purity_claim,
    check_recycled_content,
    recycled_content_receipt,
)

T0 = 1_700_000_000
AUTH = bytes([9]) * 32
AUTH_PUB = ed25519.public_key(AUTH).hex()
OTHER = bytes([7]) * 32
D1 = "ab" * 32
D2 = "cd" * 32
D3 = "ef" * 32
D4 = "01" * 32


def _recycled(sample_n=50, batch_size=1000, claim_id="rc-claim", prev="genesis"):
    return recycled_content_receipt(
        receipt_id="rc-1",
        claim_id=claim_id,
        test_protocol_digest=D1,
        batch_id="batch-7",
        batch_size=batch_size,
        measured_sample_n=sample_n,
        measured_fraction_bps=4200,
        whole_batch_measured=False,
        issued_by="lab-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
        issued_at=T0,
        expires_at=T0 + 3600,
        prev_digest=prev,
    )


def _purity(claimed=9600, measured=9500, claim_id="pur-claim"):
    return purity_claim_binding(
        receipt_id="pur-1",
        claim_id=claim_id,
        claimed_purity_bps=claimed,
        test_protocol_digest=D2,
        batch_id="shift-3",
        measured_purity_bps=measured,
        measured_sample_n=40,
        issued_by="line-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
        issued_at=T0,
        expires_at=T0 + 3600,
    )


def _evidence(tier="sensor_bound", claim_id="ev-claim"):
    return claim_evidence_receipt(
        receipt_id="ev-1",
        claim_id=claim_id,
        claim_digest=D3,
        evidence_chain_digest=D4,
        evidence_tier=tier,
        issued_by="claims-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
        issued_at=T0,
        expires_at=T0 + 3600,
    )


def _battery(inspected_at=T0, expires_at=T0 + 3600, battery_id="bat-1"):
    return battery_inspection_receipt(
        receipt_id="bat-insp-1",
        battery_id=battery_id,
        inspection_digest=D1,
        inspector="inspector-kim",
        inspected_at=inspected_at,
        expires_at=expires_at,
        issued_by="ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
    )


def _decommission(system_id="srv-1"):
    return decommission_receipt(
        receipt_id="dec-1",
        system_id=system_id,
        registration_digest=D2,
        recovery_plan_digest=D3,
        retired_at=T0,
        issued_by="dc-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
    )


class RecycledContentTests(unittest.TestCase):
    def test_valid_recycled_content_allows(self):
        log = RecycledContentLog()
        log.append(_recycled())
        verdict = check_recycled_content(log=log, claim_id="rc-claim", now=T0)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "authoritative")

    def test_single_sample_is_cherry_pick(self):
        log = RecycledContentLog()
        log.append(_recycled(sample_n=1))
        verdict = check_recycled_content(log=log, claim_id="rc-claim", now=T0)
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("greenwash.cherry_picked"))

    def test_zero_samples_is_cherry_pick(self):
        log = RecycledContentLog()
        log.append(_recycled(sample_n=0))
        verdict = check_recycled_content(log=log, claim_id="rc-claim", now=T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("cherry_picked", verdict.reason)

    def test_sample_over_batch_raises(self):
        with self.assertRaises(GreenwashError):
            _recycled(sample_n=1001, batch_size=1000)

    def test_whole_batch_mismatch_raises(self):
        with self.assertRaises(GreenwashError):
            recycled_content_receipt(
                receipt_id="rc-x", claim_id="rc-claim",
                test_protocol_digest=D1, batch_id="b", batch_size=100,
                measured_sample_n=50, measured_fraction_bps=5000,
                whole_batch_measured=True, issued_by="lab",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                issued_at=T0, expires_at=T0 + 3600,
            )

    def test_no_receipt_denies(self):
        verdict = check_recycled_content(
            log=RecycledContentLog(), claim_id="missing", now=T0
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("greenwash.no_evidence", verdict.reason)

    def test_expired_receipt_denies(self):
        log = RecycledContentLog()
        log.append(_recycled())
        verdict = check_recycled_content(log=log, claim_id="rc-claim", now=T0 + 7200)
        self.assertFalse(verdict.allowed)

    def test_chain_break_raises(self):
        log = RecycledContentLog()
        first = _recycled()
        log.append(first)
        other = recycled_content_receipt(
            receipt_id="rc-2", claim_id="rc-claim",
            test_protocol_digest=D1, batch_id="batch-8", batch_size=500,
            measured_sample_n=25, measured_fraction_bps=3000,
            issued_by="lab-ops", authority_pubkey_hex=AUTH_PUB,
            authority_secret=OTHER, issued_at=T0, expires_at=T0 + 3600,
            prev_digest="genesis",
        )
        with self.assertRaises(GreenwashError):
            log.append(other)


class MassBalanceTests(unittest.TestCase):
    def test_declared_method_allows(self):
        for method in ATTRIBUTION_METHODS:
            verdict = mass_balance_method_gate(
                claim_id="mb-1", claim_type="mass_balance", attribution_method=method
            )
            self.assertTrue(verdict.allowed, method)

    def test_undeclared_method_denies(self):
        verdict = mass_balance_method_gate(
            claim_id="mb-1", claim_type="mass_balance", attribution_method="credit_magic"
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("greenwash.undeclared_attribution"))

    def test_physical_claim_needs_no_method(self):
        verdict = mass_balance_method_gate(
            claim_id="mb-1", claim_type="physical", attribution_method="n/a-physical"
        )
        self.assertTrue(verdict.allowed)


class ClaimEvidenceTests(unittest.TestCase):
    def test_sensor_bound_allows(self):
        log = ClaimEvidenceLog()
        log.append(_evidence(tier="sensor_bound"))
        verdict = claim_evidence_chain(log=log, claim_id="ev-claim", now=T0)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "authoritative")

    def test_no_receipt_denies(self):
        verdict = claim_evidence_chain(
            log=ClaimEvidenceLog(), claim_id="ev-claim", now=T0
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("greenwash.no_evidence", verdict.reason)

    def test_self_declared_stays_non_authoritative(self):
        log = ClaimEvidenceLog()
        log.append(_evidence(tier="self_declared"))
        verdict = claim_evidence_chain(log=log, claim_id="ev-claim", now=T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("greenwash.self_declared_only", verdict.reason)
        self.assertEqual(verdict.classification, "non_authoritative")

    def test_unknown_tier_raises_at_issue(self):
        with self.assertRaises(GreenwashError):
            _evidence(tier="vibes")


class PurityClaimTests(unittest.TestCase):
    def test_measured_claim_allows(self):
        log = PurityClaimLog()
        log.append(_purity())
        verdict = check_purity_claim(
            log=log, claim_id="pur-claim", claimed_purity_bps=9550,
            test_protocol_digest=D2, now=T0,
        )
        self.assertTrue(verdict.allowed)

    def test_tolerance_edge_allows(self):
        log = PurityClaimLog()
        log.append(_purity(measured=9500))
        verdict = check_purity_claim(
            log=log, claim_id="pur-claim", claimed_purity_bps=9500 + PURITY_TOLERANCE_BPS,
            test_protocol_digest=D2, now=T0,
        )
        self.assertTrue(verdict.allowed)

    def test_no_protocol_is_ungraded(self):
        verdict = check_purity_claim(
            log=PurityClaimLog(), claim_id="pur-claim", claimed_purity_bps=9960,
            test_protocol_digest=None, now=T0,
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("greenwash.ungraded_purity"))

    def test_overclaim_denies(self):
        log = PurityClaimLog()
        log.append(_purity(measured=9000))
        verdict = check_purity_claim(
            log=log, claim_id="pur-claim", claimed_purity_bps=9960,
            test_protocol_digest=D2, now=T0,
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("greenwash.purity_overclaim"))

    def test_protocol_mismatch_denies(self):
        log = PurityClaimLog()
        log.append(_purity())
        verdict = check_purity_claim(
            log=log, claim_id="pur-claim", claimed_purity_bps=9600,
            test_protocol_digest=D4, now=T0,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("greenwash.ungraded_purity", verdict.reason)


class BatteryGateTests(unittest.TestCase):
    def test_live_inspection_allows(self):
        log = BatteryInspectionLog()
        log.append(_battery())
        verdict = battery_second_life_gate(
            log=log, battery_id="bat-1", redeploy_at=T0 + 100
        )
        self.assertTrue(verdict.allowed)

    def test_no_inspection_denies(self):
        verdict = battery_second_life_gate(
            log=BatteryInspectionLog(), battery_id="bat-1", redeploy_at=T0
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(
            verdict.reason.startswith("greenwash.no_second_life_inspection")
        )

    def test_expired_inspection_denies(self):
        log = BatteryInspectionLog()
        log.append(_battery(inspected_at=T0 - 7200, expires_at=T0 - 100))
        verdict = battery_second_life_gate(
            log=log, battery_id="bat-1", redeploy_at=T0
        )
        self.assertFalse(verdict.allowed)


class DecommissionTests(unittest.TestCase):
    def test_routed_decommission_allows(self):
        log = DecommissionLog()
        log.append(_decommission())
        verdict = decommission_path(
            log=log, system_id="srv-1",
            lookup_registration=lambda digest: digest == D2,
            now=T0 + 100,
        )
        self.assertTrue(verdict.allowed)

    def test_no_receipt_denies(self):
        verdict = decommission_path(
            log=DecommissionLog(), system_id="srv-1",
            lookup_registration=lambda digest: True, now=T0,
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(
            verdict.reason.startswith("greenwash.unrouted_decommission")
        )

    def test_unresolvable_registration_denies(self):
        log = DecommissionLog()
        log.append(_decommission())
        verdict = decommission_path(
            log=log, system_id="srv-1",
            lookup_registration=lambda digest: False,
            now=T0 + 100,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("does not resolve", verdict.reason)


class ProbeTests(unittest.TestCase):
    def test_green_claim_no_evidence_flagged(self):
        verdict = greenwash_probe(
            claim_text="Our packaging is 100% recycled and carbon neutral",
            evidence_bound=False,
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("greenwash.probe_flagged"))

    def test_non_green_claim_untouched(self):
        verdict = greenwash_probe(
            claim_text="Ships in 48 hours with free returns",
            evidence_bound=False,
        )
        self.assertTrue(verdict.allowed)

    def test_green_claim_with_authoritative_evidence_allows(self):
        verdict = greenwash_probe(
            claim_text="Sustainable sourcing for every batch",
            evidence_bound=True,
            evidence_tier="sensor_bound",
        )
        self.assertTrue(verdict.allowed)

    def test_green_claim_with_self_declared_evidence_flagged(self):
        verdict = greenwash_probe(
            claim_text="Net zero by 2030",
            evidence_bound=True,
            evidence_tier="self_declared",
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("greenwash.probe_flagged", verdict.reason)

    def test_empty_claim_raises(self):
        with self.assertRaises(GreenwashError):
            greenwash_probe(claim_text="  ", evidence_bound=False)


class AuditEventTests(unittest.TestCase):
    def test_audit_event_structure(self):
        verdict = greenwash_probe(
            claim_text="Recycled forever", evidence_bound=False
        )
        event = greenwash_audit_event(verdict, action="probe_claim")
        self.assertEqual(event["action"], "probe_claim")
        self.assertFalse(event["verdict_allowed"])
        self.assertIn("greenwash.probe_flagged", event["reason"])
        self.assertEqual(event["classification"], "non_authoritative")
        self.assertEqual(event["schema_version"], GREENWASH_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
