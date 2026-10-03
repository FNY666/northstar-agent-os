"""Tests for herd_gate (one-hundred-eighth batch)."""

import unittest

from herd_gate import (
    DENY_CORRELATED_STRATEGY,
    DENY_EXPOSURE_CAPPED,
    DENY_NO_DECLARATION,
    HERD_CORRELATION_MAX,
    HERD_EXPOSURE_CAPPED_EVENT,
    HERD_STRATEGY_DENIED_EVENT,
    HerdGateError,
    StrategyRegistry,
    build_declaration,
    check_herd_correlation,
    correlated_exposure_cents,
    jaccard_overlap,
    authorize_trading,
)

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
E = "e" * 64
F = "f" * 64


def decl(sid, sources, features, windows, corpus, by="desk-1", notional=100_00):
    return build_declaration(
        strategy_id=sid,
        signal_sources=list(sources),
        feature_families=list(features),
        data_windows=list(windows),
        training_corpus_manifest_digest=corpus,
        registered_by=by,
        declared_unix=1791057000,
        notional_cents=notional,
    )


class JaccardTest(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(jaccard_overlap(frozenset({"x"}), frozenset({"x"})), 1.0)

    def test_disjoint(self):
        self.assertEqual(jaccard_overlap(frozenset({"x"}), frozenset({"y"})), 0.0)

    def test_half(self):
        self.assertEqual(
            jaccard_overlap(frozenset({"x", "y"}), frozenset({"x", "z"})), 1 / 3
        )

    def test_empty_both(self):
        self.assertEqual(jaccard_overlap(frozenset(), frozenset()), 1.0)


class DeclarationTest(unittest.TestCase):
    def test_digest_deterministic(self):
        d1 = decl("s1", [A], ["price-momentum"], ["2026-01..2026-06"], B)
        d2 = decl("s1", [A], ["price-momentum"], ["2026-01..2026-06"], B)
        self.assertEqual(d1.declaration_digest(), d2.declaration_digest())

    def test_bad_source_hex(self):
        with self.assertRaises(HerdGateError):
            decl("s1", ["nothex"], ["price-momentum"], ["w"], B)

    def test_unknown_feature_family(self):
        with self.assertRaises(HerdGateError):
            decl("s1", [A], ["vibes"], ["w"], B)

    def test_nonpositive_notional(self):
        with self.assertRaises(HerdGateError):
            decl("s1", [A], ["price-momentum"], ["w"], B, notional=0)

    def test_bad_corpus_digest(self):
        with self.assertRaises(HerdGateError):
            decl("s1", [A], ["price-momentum"], ["w"], "zzz")


class CorrelationTest(unittest.TestCase):
    def test_identical_clone_denied(self):
        incumbent = decl("inc", [A, B], ["price-momentum", "order-book"],
                         ["2026-01..2026-06"], C)
        clone = decl("clone", [A, B], ["price-momentum", "order-book"],
                     ["2026-01..2026-06"], C, by="desk-2")
        v = check_herd_correlation(clone, [incumbent])
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CORRELATED_STRATEGY)
        self.assertEqual(v.max_overlap, 1.0)
        self.assertEqual(v.most_similar_id, "inc")

    def test_independent_allowed(self):
        incumbent = decl("inc", [A], ["price-momentum"], ["2026-01..2026-06"], B)
        other = decl("other", [C], ["news-sentiment"], ["2026-07..2026-09"], D,
                     by="desk-2")
        v = check_herd_correlation(other, [incumbent])
        self.assertTrue(v.allowed)
        self.assertLessEqual(v.max_overlap, HERD_CORRELATION_MAX)

    def test_self_excluded(self):
        d = decl("s1", [A], ["price-momentum"], ["w"], B)
        v = check_herd_correlation(d, [d])
        self.assertTrue(v.allowed)
        self.assertEqual(v.max_overlap, 0.0)

    def test_worst_of_herd_reported(self):
        near = decl("near", [A], ["price-momentum"], ["w"], B)
        far = decl("far", [C], ["news-sentiment"], ["w2"], D)
        new = decl("new", [A], ["price-momentum"], ["w"], B, by="desk-2")
        v = check_herd_correlation(new, [near, far])
        self.assertFalse(v.allowed)
        self.assertEqual(v.most_similar_id, "near")


class ExposureTest(unittest.TestCase):
    def test_no_shared_tokens_own_notional_only(self):
        a = decl("a", [A], ["price-momentum"], ["w1"], B, notional=100)
        b = decl("b", [C], ["news-sentiment"], ["w2"], D, notional=200, by="desk-2")
        self.assertEqual(correlated_exposure_cents(b, [a]), 200)

    def test_shared_token_sums(self):
        a = decl("a", [A], ["price-momentum"], ["w1"], B, notional=100)
        b = decl("b", [A], ["news-sentiment"], ["w2"], D, notional=200, by="desk-2")
        self.assertEqual(correlated_exposure_cents(b, [a]), 300)


class RegistryTest(unittest.TestCase):
    def test_register_and_lookup(self):
        reg = StrategyRegistry()
        d = decl("s1", [A], ["price-momentum"], ["w"], B)
        rec = reg.register(d)
        self.assertEqual(rec.strategy_id, "s1")
        self.assertIs(reg.declaration("s1"), d)
        self.assertTrue(reg.verify_chain())

    def test_duplicate_raises(self):
        reg = StrategyRegistry()
        reg.register(decl("s1", [A], ["price-momentum"], ["w"], B))
        with self.assertRaises(HerdGateError):
            reg.register(decl("s1", [C], ["news-sentiment"], ["w2"], D))

    def test_deregister_same_authority(self):
        reg = StrategyRegistry()
        reg.register(decl("s1", [A], ["price-momentum"], ["w"], B, by="desk-1"))
        self.assertTrue(reg.deregister("s1", "desk-1"))
        self.assertIsNone(reg.declaration("s1"))
        self.assertTrue(reg.verify_chain())

    def test_deregister_wrong_authority_raises(self):
        reg = StrategyRegistry()
        reg.register(decl("s1", [A], ["price-momentum"], ["w"], B, by="desk-1"))
        with self.assertRaises(HerdGateError):
            reg.deregister("s1", "desk-2")

    def test_deregister_unknown_returns_false(self):
        reg = StrategyRegistry()
        self.assertFalse(reg.deregister("nope", "desk-1"))


class GateTest(unittest.TestCase):
    def _registry(self):
        reg = StrategyRegistry()
        reg.register(decl("inc", [A], ["price-momentum"], ["2026-01..2026-06"],
                          B, notional=1_000_00))
        return reg

    def test_unregistered_denied(self):
        v = authorize_trading(strategy_id="ghost", registry=self._registry(),
                              exposure_cap_cents=10_000_00)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_NO_DECLARATION)
        self.assertEqual(v.audit_event["event"], HERD_STRATEGY_DENIED_EVENT)

    def test_herd_clone_denied(self):
        reg = self._registry()
        reg.register(decl("clone", [A], ["price-momentum"], ["2026-01..2026-06"],
                          B, by="desk-2", notional=500_00))
        v = authorize_trading(strategy_id="clone", registry=reg,
                              exposure_cap_cents=10_000_00)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CORRELATED_STRATEGY)
        self.assertEqual(v.audit_event["detail"]["most_similar_id"], "inc")

    def test_exposure_cap_trips(self):
        reg = self._registry()
        # Shares one source token (A) with inc -> correlated exposure 1500 > cap 1200.
        reg.register(decl("marginal", [A], ["news-sentiment"], ["2026-07..2026-09"],
                          C, by="desk-2", notional=500_00))
        v = authorize_trading(strategy_id="marginal", registry=reg,
                              exposure_cap_cents=1_200_00)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_EXPOSURE_CAPPED)
        self.assertEqual(v.audit_event["event"], HERD_EXPOSURE_CAPPED_EVENT)

    def test_clean_strategy_allowed(self):
        reg = self._registry()
        reg.register(decl("clean", [E], ["on-chain-flow"], ["2026-07..2026-09"],
                          F, by="desk-2", notional=500_00))
        v = authorize_trading(strategy_id="clean", registry=reg,
                              exposure_cap_cents=10_000_00)
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "herd_checks_passed")

    def test_malformed_inputs_raise(self):
        with self.assertRaises(HerdGateError):
            authorize_trading(strategy_id="", registry=self._registry(),
                              exposure_cap_cents=10_000_00)
        with self.assertRaises(HerdGateError):
            authorize_trading(strategy_id="inc", registry=self._registry(),
                              exposure_cap_cents=0)


if __name__ == "__main__":
    unittest.main()
