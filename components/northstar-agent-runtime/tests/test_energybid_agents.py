"""Tests for energybid_agents.py (one-hundred-forty-fifth batch)."""

import unittest

import ed25519

import energybid_agents
from energybid_agents import (
    AlgorithmRegistry,
    BidEvidenceLog,
    CorrelationLog,
    EnergyBidError,
    KillSwitchLog,
    NegativePriceLog,
    PositionRegistry,
    ResourcePinLog,
    TradeLog,
    algorithm_registry_receipt,
    bid_evidence_binding,
    check_algorithm,
    check_correlation_cap,
    check_kill_switch,
    check_negative_price_bid,
    check_position_limit,
    check_quote_evidence,
    check_resource_pin,
    check_trade_explainability,
    correlation_circuit_breaker,
    cross_market_position_limit,
    human_kill_switch,
    negative_price_declaration,
    post_trade_explainability,
    resource_registry_pin,
)

_SEED = bytes(range(32))
_PUBKEY = ed25519.public_key(_SEED).hex()
_T0 = 1_800_000_000
_T1 = 1_800_003_600
_HEX64 = "ab" * 32
_HEX64_B = "cd" * 32


def _bid_log(now_issued=_T0, now_expiry=_T1):
    log = BidEvidenceLog()
    log.append(
        bid_evidence_binding(
            receipt_id="be-1", quote_id="q-1", participant_id="p-a",
            market="day_ahead", model_version="v3", input_data_digest=_HEX64,
            rule_version="r9", issued_by="op", authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED, issued_at=now_issued, expires_at=now_expiry,
        )
    )
    return log


class BidEvidenceTest(unittest.TestCase):
    def test_bound_quote_allows(self):
        v = check_quote_evidence(log=_bid_log(), quote_id="q-1", now=_T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_unbound_quote_is_non_authoritative(self):
        v = check_quote_evidence(log=BidEvidenceLog(), quote_id="q-ghost", now=_T0)
        self.assertFalse(v.allowed)
        self.assertIn("unbound_quote", v.reason)

    def test_expired_evidence_denies(self):
        log = _bid_log(now_issued=_T0, now_expiry=_T0 + 10)
        v = check_quote_evidence(log=log, quote_id="q-1", now=_T0 + 11)
        self.assertFalse(v.allowed)
        self.assertIn("unbound_quote", v.reason)

    def test_expiry_before_issuance_is_a_bug(self):
        with self.assertRaises(EnergyBidError):
            bid_evidence_binding(
                receipt_id="be-x", quote_id="q-x", participant_id="p-a",
                market="day_ahead", model_version="v3", input_data_digest=_HEX64,
                rule_version="r9", issued_by="op", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T1, expires_at=_T0,
            )


class ResourcePinTest(unittest.TestCase):
    def _log(self):
        log = ResourcePinLog()
        log.append(
            resource_registry_pin(
                receipt_id="rp-1", resource_id="res-1", participant_id="p-a",
                market="balancing", capacity_mw=100, contract_chain_digest=_HEX64,
                issued_by="registry", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T0, expires_at=_T1,
            )
        )
        return log

    def test_covered_capacity_allows(self):
        v = check_resource_pin(
            log=self._log(), participant_id="p-a", market="balancing",
            capacity_mw=80, now=_T0,
        )
        self.assertTrue(v.allowed)

    def test_uncovered_capacity_denies_no_contract_chain(self):
        v = check_resource_pin(
            log=self._log(), participant_id="p-a", market="balancing",
            capacity_mw=150, now=_T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("no_contract_chain", v.reason)

    def test_wrong_market_denies(self):
        v = check_resource_pin(
            log=self._log(), participant_id="p-a", market="capacity",
            capacity_mw=10, now=_T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("no_contract_chain", v.reason)

    def test_zero_capacity_pin_is_a_bug(self):
        with self.assertRaises(EnergyBidError):
            resource_registry_pin(
                receipt_id="rp-x", resource_id="res-x", participant_id="p-a",
                market="balancing", capacity_mw=0, contract_chain_digest=_HEX64,
                issued_by="registry", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T0, expires_at=_T1,
            )


class CorrelationCapTest(unittest.TestCase):
    def _log(self, bps):
        log = CorrelationLog()
        log.append(
            correlation_circuit_breaker(
                receipt_id="cc-1", participant_a="p-a", participant_b="p-b",
                correlation_bps=bps, measured_by="ferc-surveillance",
                authority_pubkey_hex=_PUBKEY, authority_secret=_SEED,
                measured_at=_T0, expires_at=_T1,
            )
        )
        return log

    def test_below_threshold_allows(self):
        v = check_correlation_cap(
            log=self._log(6000), participant_id="p-a", position_mw=500,
            cap_mw=100, threshold_bps=9000, now=_T0,
        )
        self.assertTrue(v.allowed)

    def test_above_threshold_over_cap_denies(self):
        v = check_correlation_cap(
            log=self._log(9500), participant_id="p-a", position_mw=150,
            cap_mw=100, threshold_bps=9000, now=_T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("correlation_position_cap", v.reason)

    def test_above_threshold_under_cap_allows(self):
        v = check_correlation_cap(
            log=self._log(9500), participant_id="p-a", position_mw=50,
            cap_mw=100, threshold_bps=9000, now=_T0,
        )
        self.assertTrue(v.allowed)

    def test_self_comparison_is_a_bug(self):
        with self.assertRaises(EnergyBidError):
            correlation_circuit_breaker(
                receipt_id="cc-x", participant_a="p-a", participant_b="p-a",
                correlation_bps=10000, measured_by="x",
                authority_pubkey_hex=_PUBKEY, authority_secret=_SEED,
                measured_at=_T0, expires_at=_T1,
            )


class PositionLimitTest(unittest.TestCase):
    def _registry(self):
        reg = PositionRegistry()
        prev = "genesis"
        for cid, market, mw in (("c-1", "day_ahead", 100), ("c-2", "balancing", 80)):
            c = cross_market_position_limit(
                commitment_id=cid, participant_id="p-a", market=market,
                committed_mw=mw, participant_pubkey_hex=_PUBKEY,
                participant_secret=_SEED, declared_at=_T0, prev_digest=prev,
            )
            reg.append(c)
            prev = c.receipt_digest
        return reg

    def test_within_registered_capacity_allows(self):
        v = check_position_limit(
            registry=self._registry(), participant_id="p-a",
            registered_capacity_mw=200,
        )
        self.assertTrue(v.allowed)

    def test_double_sold_denies(self):
        v = check_position_limit(
            registry=self._registry(), participant_id="p-a",
            registered_capacity_mw=150,
        )
        self.assertFalse(v.allowed)
        self.assertIn("double_sold", v.reason)

    def test_tampered_participant_signature_rejected(self):
        reg = PositionRegistry()
        c = cross_market_position_limit(
            commitment_id="c-x", participant_id="p-a", market="intraday",
            committed_mw=10, participant_pubkey_hex=_PUBKEY,
            participant_secret=_SEED, declared_at=_T0,
        )
        bad = energybid_agents.PositionCommitment(
            **{**c.__dict__, "committed_mw": 9999}
        )
        with self.assertRaises(EnergyBidError):
            reg.append(bad)


class NegativePriceTest(unittest.TestCase):
    def _log(self):
        log = NegativePriceLog()
        log.append(
            negative_price_declaration(
                receipt_id="np-1", declaration_id="npd-1", participant_id="p-a",
                market="intraday", strategy_id="auto-stop-feed-in",
                issued_by="market-op", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T0, expires_at=_T1,
            )
        )
        return log

    def test_declared_negative_bid_allows(self):
        v = check_negative_price_bid(
            log=self._log(), participant_id="p-a", market="intraday",
            price_is_negative=True, now=_T0,
        )
        self.assertTrue(v.allowed)

    def test_undeclared_negative_bid_denies(self):
        v = check_negative_price_bid(
            log=NegativePriceLog(), participant_id="p-a", market="intraday",
            price_is_negative=True, now=_T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("undeclared_negative_price", v.reason)

    def test_positive_bid_needs_no_declaration(self):
        v = check_negative_price_bid(
            log=NegativePriceLog(), participant_id="p-a", market="intraday",
            price_is_negative=False, now=_T0,
        )
        self.assertTrue(v.allowed)


class AlgorithmRegistryTest(unittest.TestCase):
    def _log(self, revoked=False):
        log = AlgorithmRegistry()
        log.append(
            algorithm_registry_receipt(
                receipt_id="ar-1", registration_id="reg-1", algorithm_id="algo-7",
                participant_id="p-a", model_version="v3",
                responsible_person="Jane Operator", revoked=revoked,
                issued_by="market-op", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T0, expires_at=_T1,
            )
        )
        return log

    def test_registered_algorithm_allows(self):
        v = check_algorithm(log=self._log(), algorithm_id="algo-7", now=_T0)
        self.assertTrue(v.allowed)
        self.assertIn("Jane Operator", v.reason)

    def test_unregistered_algorithm_denies(self):
        v = check_algorithm(log=self._log(), algorithm_id="algo-ghost", now=_T0)
        self.assertFalse(v.allowed)
        self.assertIn("unregistered_algorithm", v.reason)

    def test_revoked_registration_denies(self):
        v = check_algorithm(log=self._log(revoked=True), algorithm_id="algo-7", now=_T0)
        self.assertFalse(v.allowed)
        self.assertIn("unregistered_algorithm", v.reason)

    def test_anonymous_algorithm_cannot_register(self):
        with self.assertRaises(EnergyBidError):
            algorithm_registry_receipt(
                receipt_id="ar-x", registration_id="reg-x", algorithm_id="algo-x",
                participant_id="p-a", model_version="v3", responsible_person="  ",
                issued_by="market-op", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T0, expires_at=_T1,
            )


class ExplainabilityTest(unittest.TestCase):
    def _log(self):
        log = TradeLog()
        log.append(
            post_trade_explainability(
                receipt_id="ex-1", trade_id="t-1", quote_digest=_HEX64,
                explainer_model_version="xgb-explainer-v2",
                narrative_digest=_HEX64_B, issued_by="p-a",
                authority_pubkey_hex=_PUBKEY, authority_secret=_SEED,
                issued_at=_T0,
            )
        )
        return log

    def test_explained_trade_allows_authoritative(self):
        v = check_trade_explainability(log=self._log(), trade_id="t-1")
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_unexplained_trade_is_non_authoritative(self):
        v = check_trade_explainability(log=self._log(), trade_id="t-ghost")
        self.assertFalse(v.allowed)
        self.assertIn("no_explainability", v.reason)


class KillSwitchTest(unittest.TestCase):
    def _log(self, last_test_at, interval):
        log = KillSwitchLog()
        log.append(
            human_kill_switch(
                receipt_id="ks-1", switch_id="sw-1", participant_id="p-a",
                test_interval_s=interval, last_test_at=last_test_at,
                issued_by="authority", authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED, issued_at=_T0,
            )
        )
        return log

    def test_tested_switch_allows(self):
        v = check_kill_switch(log=self._log(_T0, 3600), participant_id="p-a", now=_T0 + 100)
        self.assertTrue(v.allowed)

    def test_stale_test_is_dead_switch(self):
        v = check_kill_switch(log=self._log(_T0, 3600), participant_id="p-a", now=_T0 + 7200)
        self.assertFalse(v.allowed)
        self.assertIn("dead_switch", v.reason)

    def test_missing_switch_is_dead_switch(self):
        v = check_kill_switch(log=KillSwitchLog(), participant_id="p-a", now=_T0)
        self.assertFalse(v.allowed)
        self.assertIn("dead_switch", v.reason)

    def test_zero_interval_is_a_bug(self):
        with self.assertRaises(EnergyBidError):
            human_kill_switch(
                receipt_id="ks-x", switch_id="sw-x", participant_id="p-a",
                test_interval_s=0, last_test_at=_T0, issued_by="authority",
                authority_pubkey_hex=_PUBKEY, authority_secret=_SEED,
                issued_at=_T0,
            )


class ChainIntegrityTest(unittest.TestCase):
    def test_tampered_receipt_breaks_chain(self):
        log = _bid_log()
        r = log._log[0]
        tampered = energybid_agents.BidEvidenceReceipt(
            **{**r.__dict__, "model_version": "evil-v9"}
        )
        with self.assertRaises(EnergyBidError):
            energybid_agents._check_chain([tampered], "bid-evidence")

    def test_broken_prev_link_rejected_on_append(self):
        log = BidEvidenceLog()
        r = bid_evidence_binding(
            receipt_id="be-x", quote_id="q-x", participant_id="p-a",
            market="day_ahead", model_version="v3", input_data_digest=_HEX64,
            rule_version="r9", issued_by="op", authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED, issued_at=_T0, expires_at=_T1,
            prev_digest="00" * 32,
        )
        with self.assertRaises(EnergyBidError):
            log.append(r)


if __name__ == "__main__":
    unittest.main()
