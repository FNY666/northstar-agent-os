"""Tests for mining_agents.py (one-hundred-thirty-second batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

import ed25519

from mining_agents import (
    AuthorityRegistry,
    DataSovereigntyLog,
    ExplorationLog,
    FPICLog,
    FleetEnvelopeLog,
    GreenClaimLog,
    LaborTransitionLog,
    MixedTrafficLog,
    MiningError,
    TailingsMonitorLog,
    TAILINGS_FRESHNESS_S,
    autonomous_fleet_envelope,
    check_data_export,
    check_labor_transition,
    exploration_target_receipt,
    exploration_transparency,
    fleet_envelope_receipt,
    fpic_gate,
    fpic_receipt,
    green_claim_receipt,
    green_mining_gate,
    labor_transition_receipt,
    mixed_fleet_rule,
    mixed_traffic_receipt,
    sovereignty_receipt,
    tailings_monitor_gate,
    tailings_monitoring_receipt,
)

T0 = 1_700_000_000
AUTH = bytes([9]) * 32
AUTH_PUB = ed25519.public_key(AUTH).hex()
OTHER = bytes([7]) * 32
D1 = "ab" * 32
D2 = "cd" * 32


def _auth():
    reg = AuthorityRegistry()
    reg.register("gov", ed25519.public_key(AUTH))
    return reg


def _fpic(log, rid, site, community, prev, secret=AUTH, issued_at=T0,
          expires_at=T0 + 3600):
    return log.append(
        fpic_receipt(
            receipt_id=rid, site_id=site, community_id=community,
            process_digest=D1, issued_by="gov",
            authority_pubkey_hex=AUTH_PUB, authority_secret=secret,
            issued_at=issued_at, expires_at=expires_at, prev_digest=prev,
        )
    )


class FPICGateTests(unittest.TestCase):
    def test_all_communities_consented_allows(self):
        auth = _auth()
        log = FPICLog()
        r1 = _fpic(log, "r1", "s1", "c1", "genesis")
        _fpic(log, "r2", "s1", "c2", r1.receipt_digest)
        v = fpic_gate(authorities=auth, log=log, site_id="s1",
                      affected_communities=("c1", "c2"), now=T0)
        self.assertTrue(v.allowed)
        self.assertIsNone(v.deny_code)

    def test_one_missing_community_denies_whole_class(self):
        auth = _auth()
        log = FPICLog()
        _fpic(log, "r1", "s1", "c1", "genesis")
        v = fpic_gate(authorities=auth, log=log, site_id="s1",
                      affected_communities=("c1", "c2"), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:no_fpic")

    def test_expired_receipt_denies(self):
        auth = _auth()
        log = FPICLog()
        _fpic(log, "r1", "s1", "c1", "genesis", issued_at=T0 - 7200,
              expires_at=T0 - 3600)
        v = fpic_gate(authorities=auth, log=log, site_id="s1",
                      affected_communities=("c1",), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:fpic_expired")

    def test_revoked_receipt_denies(self):
        auth = _auth()
        log = FPICLog()
        r1 = _fpic(log, "r1", "s1", "c1", "genesis")
        log.revoke(r1.receipt_id)
        v = fpic_gate(authorities=auth, log=log, site_id="s1",
                      affected_communities=("c1",), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:fpic_revoked")

    def test_tampered_receipt_denies(self):
        auth = _auth()
        log = FPICLog()
        r1 = _fpic(log, "r1", "s1", "c1", "genesis")
        object.__setattr__  # frozen dataclass: mutate via replacement
        bad = r1.__class__(**{**r1.__dict__, "process_digest": D2})
        log2 = FPICLog()
        with self.assertRaises(MiningError):
            log2.append(bad)  # chain digest check fails on append


class TailingsGateTests(unittest.TestCase):
    def _monitor(self, log, rid, dam, prev, last_reading_at=T0):
        return log.append(
            tailings_monitoring_receipt(
                receipt_id=rid, dam_id=dam, sensor_set_digest=D1,
                last_reading_at=last_reading_at, reading_digest=D2,
                issued_by="gov", authority_pubkey_hex=AUTH_PUB,
                authority_secret=AUTH, issued_at=T0, prev_digest=prev,
            )
        )

    def test_live_monitoring_allows(self):
        auth = _auth()
        log = TailingsMonitorLog()
        self._monitor(log, "m1", "dam1", "genesis")
        verdict, incident = tailings_monitor_gate(
            authorities=auth, log=log, dam_id="dam1", now=T0)
        self.assertTrue(verdict.allowed)
        self.assertIsNone(incident)

    def test_missing_monitoring_denies_and_emits_watchdog(self):
        auth = _auth()
        log = TailingsMonitorLog()
        verdict, incident = tailings_monitor_gate(
            authorities=auth, log=log, dam_id="dam-ghost", now=T0)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.deny_code, "mining:no_tailings_monitor")
        self.assertIsNotNone(incident)
        self.assertEqual(incident.kind, "no_monitoring")

    def test_stale_reading_denies_and_emits_watchdog(self):
        auth = _auth()
        log = TailingsMonitorLog()
        self._monitor(log, "m1", "dam1", "genesis",
                      last_reading_at=T0 - TAILINGS_FRESHNESS_S - 1)
        verdict, incident = tailings_monitor_gate(
            authorities=auth, log=log, dam_id="dam1", now=T0)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.deny_code, "mining:stale_tailings_monitor")
        self.assertIsNotNone(incident)
        self.assertEqual(incident.kind, "stale_monitoring")


class ExplorationTests(unittest.TestCase):
    def test_disclosed_target_allows(self):
        auth = _auth()
        log = ExplorationLog()
        log.append(
            exploration_target_receipt(
                receipt_id="e1", target_id="t1", evidence_digest=D1,
                model_digest=D2, issued_by="gov",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                issued_at=T0, prev_digest="genesis",
            )
        )
        v = exploration_transparency(authorities=auth, log=log, target_id="t1")
        self.assertTrue(v.allowed)

    def test_undisclosed_target_is_non_authoritative(self):
        auth = _auth()
        log = ExplorationLog()
        v = exploration_transparency(authorities=auth, log=log, target_id="t-x")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:undisclosed_targeting")
        self.assertEqual(v.classification, "mining-non-authoritative")


class FleetEnvelopeTests(unittest.TestCase):
    def _envelope(self, log, rid, fleet, vocab, prev):
        return log.append(
            fleet_envelope_receipt(
                receipt_id=rid, fleet_id=fleet,
                action_vocabulary=vocab, geographic_scope_digest=D1,
                issued_by="gov", authority_pubkey_hex=AUTH_PUB,
                authority_secret=AUTH, issued_at=T0,
                expires_at=T0 + 3600, prev_digest=prev,
            )
        )

    def test_in_envelope_action_allows(self):
        auth = _auth()
        log = FleetEnvelopeLog()
        self._envelope(log, "f1", "fleet1", ("haul", "dump"), "genesis")
        v = autonomous_fleet_envelope(
            authorities=auth, log=log, fleet_id="fleet1", action="haul",
            requested_by="dispatch", now=T0)
        self.assertTrue(v.allowed)

    def test_out_of_envelope_action_denies(self):
        auth = _auth()
        log = FleetEnvelopeLog()
        self._envelope(log, "f1", "fleet1", ("haul",), "genesis")
        v = autonomous_fleet_envelope(
            authorities=auth, log=log, fleet_id="fleet1", action="dump",
            requested_by="dispatch", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:fleet_out_of_envelope")

    def test_self_widening_denies(self):
        auth = _auth()
        log = FleetEnvelopeLog()
        self._envelope(log, "f1", "fleet1", ("haul",), "genesis")
        v = autonomous_fleet_envelope(
            authorities=auth, log=log, fleet_id="fleet1", action="dump",
            requested_by="fleet1", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:envelope_widened")

    def test_no_envelope_denies(self):
        auth = _auth()
        log = FleetEnvelopeLog()
        v = autonomous_fleet_envelope(
            authorities=auth, log=log, fleet_id="fleet-ghost",
            action="haul", requested_by="dispatch", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:no_fleet_envelope")


class MixedTrafficTests(unittest.TestCase):
    def test_mixed_traffic_with_protocol_allows(self):
        auth = _auth()
        log = MixedTrafficLog()
        log.append(
            mixed_traffic_receipt(
                receipt_id="mt1", site_id="s1", protocol_digest=D1,
                protocol_version="v3", issued_by="gov",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                issued_at=T0, expires_at=T0 + 3600, prev_digest="genesis",
            )
        )
        v = mixed_fleet_rule(authorities=auth, log=log, site_id="s1",
                             mixed_traffic=True, now=T0)
        self.assertTrue(v.allowed)

    def test_mixed_traffic_without_protocol_denies(self):
        auth = _auth()
        log = MixedTrafficLog()
        v = mixed_fleet_rule(authorities=auth, log=log, site_id="s1",
                             mixed_traffic=True, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:no_mixed_traffic_protocol")

    def test_pure_autonomous_out_of_scope(self):
        auth = _auth()
        log = MixedTrafficLog()
        v = mixed_fleet_rule(authorities=auth, log=log, site_id="s1",
                             mixed_traffic=False, now=T0)
        self.assertTrue(v.allowed)


class LaborTransitionTests(unittest.TestCase):
    def test_below_threshold_out_of_scope(self):
        auth = _auth()
        log = LaborTransitionLog()
        v = check_labor_transition(authorities=auth, log=log, site_id="s1",
                                   displaced_count=5, now=T0)
        self.assertTrue(v.allowed)

    def test_displacement_without_plan_denies(self):
        auth = _auth()
        log = LaborTransitionLog()
        v = check_labor_transition(authorities=auth, log=log, site_id="s1",
                                   displaced_count=40, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:transition_plan_undisclosed")

    def test_published_plan_allows(self):
        auth = _auth()
        log = LaborTransitionLog()
        log.append(
            labor_transition_receipt(
                receipt_id="lt1", site_id="s1",
                displaced_roles=("driver",), displaced_count=40,
                plan_digest=D1, published_at=T0, issued_by="gov",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                prev_digest="genesis",
            )
        )
        v = check_labor_transition(authorities=auth, log=log, site_id="s1",
                                   displaced_count=40, now=T0)
        self.assertTrue(v.allowed)


class DataSovereigntyTests(unittest.TestCase):
    def test_authorized_export_allows(self):
        auth = _auth()
        log = DataSovereigntyLog()
        log.append(
            sovereignty_receipt(
                receipt_id="ds1", dataset_id="geo-1", host_country="CD",
                export_purpose="model-training", authorized_by="gov",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                issued_at=T0, expires_at=T0 + 3600, prev_digest="genesis",
            )
        )
        v = check_data_export(authorities=auth, log=log, dataset_id="geo-1",
                              destination_country="US", host_country="CD",
                              now=T0)
        self.assertTrue(v.allowed)

    def test_unauthorized_export_denies(self):
        auth = _auth()
        log = DataSovereigntyLog()
        v = check_data_export(authorities=auth, log=log, dataset_id="geo-x",
                              destination_country="US", host_country="CD",
                              now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:unauthorized_data_export")

    def test_domestic_use_out_of_scope(self):
        auth = _auth()
        log = DataSovereigntyLog()
        v = check_data_export(authorities=auth, log=log, dataset_id="geo-1",
                              destination_country="CD", host_country="CD",
                              now=T0)
        self.assertTrue(v.allowed)


class GreenMiningTests(unittest.TestCase):
    def test_bound_claim_allows(self):
        auth = _auth()
        log = GreenClaimLog()
        log.append(
            green_claim_receipt(
                receipt_id="g1", claim_id="green-1", ledger_digest=D1,
                measured_scope="scope-3-site", issued_by="gov",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                issued_at=T0, prev_digest="genesis",
            )
        )
        v = green_mining_gate(authorities=auth, log=log, claim_id="green-1",
                              ledger_digest=D1)
        self.assertTrue(v.allowed)

    def test_unbound_claim_is_non_authoritative(self):
        auth = _auth()
        log = GreenClaimLog()
        v = green_mining_gate(authorities=auth, log=log, claim_id="green-x",
                              ledger_digest=None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:unsubstantiated_green_claim")

    def test_ledger_mismatch_denies(self):
        auth = _auth()
        log = GreenClaimLog()
        log.append(
            green_claim_receipt(
                receipt_id="g1", claim_id="green-1", ledger_digest=D1,
                measured_scope="scope-3-site", issued_by="gov",
                authority_pubkey_hex=AUTH_PUB, authority_secret=AUTH,
                issued_at=T0, prev_digest="genesis",
            )
        )
        v = green_mining_gate(authorities=auth, log=log, claim_id="green-1",
                              ledger_digest=D2)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "mining:green_digest_mismatch")


if __name__ == "__main__":
    unittest.main()
