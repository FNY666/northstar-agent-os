"""Tests for synthetic_cap (one-hundred-twelfth batch)."""

import hashlib
import unittest

from synthetic_cap import (
    ART50_GRACE_CUTOFF_EPOCH_DAYS,
    DENY_ART50_MARKING_MISSING,
    DENY_LINEAGE_PIN_MISMATCH,
    DENY_MALFORMED,
    DENY_MANIFEST_CHAIN_BROKEN,
    DENY_MANIFEST_TAMPERED,
    DENY_RATIO_EXCEEDED,
    DENY_RECURSIVE_REUSE,
    DENY_UNDECLARED_SLICE,
    SYNTHETIC_RATIO_MAX,
    DataSliceManifest,
    SyntheticCapError,
    art50_gate,
    check_synthetic_ratio,
    check_tdm_optout,
    issue_slice_manifest,
    manifest_set_digest,
    pin_to_lineage,
    training_summary_receipt,
    verify_manifest_set,
    verify_training_summary,
)

SEED_A = bytes(range(32))
SEED_B = bytes([255 - i for i in range(32)])


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _real(sid, weight=100, seed=SEED_A, prev="genesis"):
    return issue_slice_manifest(
        slice_id=sid,
        origin="real",
        slice_digest=_digest("content-" + sid),
        weight_units=weight,
        issued_at=1000,
        authority_secret=seed,
        prev_digest=prev,
    )


def _synth(sid, weight=100, generation=1, seed=SEED_A, prev="genesis"):
    return issue_slice_manifest(
        slice_id=sid,
        origin="synthetic",
        slice_digest=_digest("content-" + sid),
        weight_units=weight,
        generator_id="gen-gretel-1",
        generation=generation,
        issued_at=1000,
        authority_secret=seed,
        prev_digest=prev,
    )


class TestIssueAndIntegrity(unittest.TestCase):
    def test_chain_verifies(self):
        a = _real("s1")
        b = _real("s2", prev=a.manifest_digest)
        self.assertIsNone(verify_manifest_set([a, b]))

    def test_tampered_digest_detected(self):
        a = _real("s1")
        import dataclasses
        bad = dataclasses.replace(a, slice_digest=_digest("evil"))
        self.assertEqual(verify_manifest_set([bad]), DENY_MANIFEST_TAMPERED)

    def test_chain_break_detected(self):
        a = _real("s1")
        b = _real("s2", prev="00" * 32)
        self.assertEqual(verify_manifest_set([a, b]), DENY_MANIFEST_CHAIN_BROKEN)

    def test_real_slice_with_generator_rejected(self):
        with self.assertRaises(SyntheticCapError):
            issue_slice_manifest(
                slice_id="s1", origin="real", slice_digest=_digest("x"),
                weight_units=1, generator_id="g", issued_at=1,
                authority_secret=SEED_A,
            )

    def test_real_slice_with_generation_rejected(self):
        with self.assertRaises(SyntheticCapError):
            issue_slice_manifest(
                slice_id="s1", origin="real", slice_digest=_digest("x"),
                weight_units=1, generation=1, issued_at=1,
                authority_secret=SEED_A,
            )

    def test_synthetic_without_generator_rejected(self):
        with self.assertRaises(SyntheticCapError):
            issue_slice_manifest(
                slice_id="s1", origin="synthetic", slice_digest=_digest("x"),
                weight_units=1, generation=1, issued_at=1,
                authority_secret=SEED_A,
            )

    def test_wrong_seed_fails_signature(self):
        a = _real("s1")
        import dataclasses
        bad = dataclasses.replace(a, authority_pubkey_hex="ab" * 32)
        self.assertEqual(verify_manifest_set([bad]), DENY_MANIFEST_TAMPERED)


class TestRatioCap(unittest.TestCase):
    def _set(self, specs):
        out = []
        prev = "genesis"
        for sid, origin, weight, gen in specs:
            if origin == "real":
                m = _real(sid, weight=weight, prev=prev)
            else:
                m = _synth(sid, weight=weight, generation=gen, prev=prev)
            prev = m.manifest_digest
            out.append(m)
        return out

    def test_all_real_allows(self):
        ms = self._set([("a", "real", 100, 0), ("b", "real", 100, 0)])
        v = check_synthetic_ratio(ms, ["a", "b"])
        self.assertTrue(v.allowed)
        self.assertEqual(v.synthetic_fraction, 0.0)

    def test_under_cap_allows(self):
        ms = self._set([("a", "real", 60, 0), ("b", "synthetic", 40, 1)])
        v = check_synthetic_ratio(ms, ["a", "b"])
        self.assertTrue(v.allowed)
        self.assertAlmostEqual(v.synthetic_fraction, 0.4)

    def test_over_cap_denies(self):
        ms = self._set([("a", "real", 40, 0), ("b", "synthetic", 60, 1)])
        v = check_synthetic_ratio(ms, ["a", "b"])
        self.assertFalse(v.allowed)
        self.assertIn(DENY_RATIO_EXCEEDED, v.reason)

    def test_generation2_denies_even_under_cap(self):
        # The RAG-collapse tripwire fires regardless of the ratio.
        ms = self._set([("a", "real", 90, 0), ("b", "synthetic", 10, 2)])
        v = check_synthetic_ratio(ms, ["a", "b"])
        self.assertFalse(v.allowed)
        self.assertIn(DENY_RECURSIVE_REUSE, v.reason)
        self.assertTrue(v.recursion_detected)

    def test_undeclared_slice_denies(self):
        ms = self._set([("a", "real", 100, 0)])
        v = check_synthetic_ratio(ms, ["a", "ghost"])
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNDECLARED_SLICE, v.reason)

    def test_zero_weight_denies_malformed(self):
        ms = self._set([("a", "real", 0, 0)])
        v = check_synthetic_ratio(ms, ["a"])
        self.assertFalse(v.allowed)
        self.assertIn(DENY_MALFORMED, v.reason)

    def test_custom_cap_is_honored(self):
        ms = self._set([("a", "real", 70, 0), ("b", "synthetic", 30, 1)])
        v = check_synthetic_ratio(ms, ["a", "b"], ratio_max=0.2)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_RATIO_EXCEEDED, v.reason)


class TestTDMPOptout(unittest.TestCase):
    def test_machine_readable_honored(self):
        v = check_tdm_optout({
            "source_id": "src-1",
            "tdm_optout_machine_readable": True,
            "tdm_optout_tos_prose": True,
        })
        self.assertTrue(v.honored)

    def test_prose_only_not_honored(self):
        # Kneschke v. LAION: prose alone does not count — but the
        # source is not denied either; it is simply usable.
        v = check_tdm_optout({
            "source_id": "src-2",
            "tdm_optout_machine_readable": False,
            "tdm_optout_tos_prose": True,
        })
        self.assertFalse(v.honored)
        self.assertIn("Kneschke", v.reason)

    def test_no_signal_not_honored(self):
        v = check_tdm_optout({"source_id": "src-3"})
        self.assertFalse(v.honored)


class TestArt50Gate(unittest.TestCase):
    def test_non_eu_not_applicable(self):
        v = art50_gate(
            jurisdiction="non-eu", machine_readable_marking=False,
            placed_on_market_epoch_days=20000, now_epoch_days=20800,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_eu_marked_allows(self):
        v = art50_gate(
            jurisdiction="eu", machine_readable_marking=True,
            placed_on_market_epoch_days=20800, now_epoch_days=20800,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_eu_grace_window_non_authoritative(self):
        v = art50_gate(
            jurisdiction="eu", machine_readable_marking=False,
            placed_on_market_epoch_days=ART50_GRACE_CUTOFF_EPOCH_DAYS - 10,
            now_epoch_days=ART50_GRACE_CUTOFF_EPOCH_DAYS - 1,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "non_authoritative")

    def test_eu_post_grace_denies(self):
        v = art50_gate(
            jurisdiction="eu", machine_readable_marking=False,
            placed_on_market_epoch_days=ART50_GRACE_CUTOFF_EPOCH_DAYS,
            now_epoch_days=ART50_GRACE_CUTOFF_EPOCH_DAYS + 1,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_ART50_MARKING_MISSING, v.reason)

    def test_unknown_jurisdiction_rejected(self):
        with self.assertRaises(SyntheticCapError):
            art50_gate(
                jurisdiction="mars", machine_readable_marking=True,
                placed_on_market_epoch_days=1, now_epoch_days=2,
            )


class TestTrainingSummary(unittest.TestCase):
    def _set(self):
        out, prev = [], "genesis"
        for sid, origin, weight, gen in [
            ("a", "real", 500, 0), ("b", "synthetic", 200, 1),
            ("c", "real", 300, 0),
        ]:
            if origin == "real":
                m = _real(sid, weight=weight, prev=prev)
            else:
                m = _synth(sid, weight=weight, generation=gen, prev=prev)
            prev = m.manifest_digest
            out.append(m)
        return out

    def test_summary_round_trips(self):
        ms = self._set()
        r = training_summary_receipt(model_id="m-1", manifests=ms, issued_at=5)
        self.assertTrue(verify_training_summary(r, ms))
        # top-source template: ranked by weight
        self.assertEqual([t[0] for t in r.top_sources], ["a", "c", "b"])
        self.assertAlmostEqual(r.synthetic_fraction, 0.2)

    def test_summary_rejects_tampered_manifests(self):
        ms = self._set()
        r = training_summary_receipt(model_id="m-1", manifests=ms, issued_at=5)
        import dataclasses
        tampered = dataclasses.replace(ms[0], weight_units=1)
        self.assertFalse(verify_training_summary(r, [tampered] + ms[1:]))

    def test_pin_to_lineage_matches(self):
        ms = self._set()

        class FakeReceipt:
            corpus_manifest_digest = manifest_set_digest(ms)

        v = pin_to_lineage(FakeReceipt(), ms)
        self.assertTrue(v.allowed)

    def test_pin_to_lineage_mismatch_denies(self):
        ms = self._set()

        class FakeReceipt:
            corpus_manifest_digest = "ff" * 32

        v = pin_to_lineage(FakeReceipt(), ms)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LINEAGE_PIN_MISMATCH, v.reason)


if __name__ == "__main__":
    unittest.main()
