"""Tests for model_lineage.py (one-hundredth batch)."""

import hashlib
import unittest

from model_lineage import (
    ACQUISITION_METHODS,
    UNVERIFIABLE_LINEAGE,
    VERIFIED_LINEAGE,
    LineageReceiptError,
    build_receipt,
    classify_model,
    compute_receipt_digest,
    verify_lineage,
)


def _hex(label: str) -> str:
    return hashlib.sha256(f"northstar-test-model-lineage:{label}".encode()).hexdigest()


def _consent_db(*ids: str) -> dict[str, dict]:
    return {rid: {"granted": True, "scope": "training"} for rid in ids}


class LineageConstructionTests(unittest.TestCase):
    def test_build_seals_digest(self):
        r = build_receipt(
            model_id="m1",
            model_digest=_hex("m1"),
            corpus_manifest_digest=_hex("corpus1"),
            acquisition_method="licensed",
            timestamp=1000,
        )
        self.assertEqual(r.receipt_digest, compute_receipt_digest(r))

    def test_unknown_acquisition_method_rejected(self):
        with self.assertRaises(LineageReceiptError):
            build_receipt(
                model_id="m1",
                model_digest=_hex("m1"),
                corpus_manifest_digest=_hex("c"),
                acquisition_method="torrent",
                timestamp=1000,
            )

    def test_consent_ids_require_consent_gated(self):
        with self.assertRaises(LineageReceiptError):
            build_receipt(
                model_id="m1",
                model_digest=_hex("m1"),
                corpus_manifest_digest=_hex("c"),
                acquisition_method="licensed",
                consent_receipt_ids=("cr-1",),
                timestamp=1000,
            )

    def test_bad_digest_rejected(self):
        with self.assertRaises(LineageReceiptError):
            build_receipt(
                model_id="m1",
                model_digest="not-hex",
                corpus_manifest_digest=_hex("c"),
                acquisition_method="licensed",
                timestamp=1000,
            )


class LineageVerificationTests(unittest.TestCase):
    def _chain(self, **kw):
        """Three-generation clean chain: licensed root -> consent-gated -> public-domain."""
        root = build_receipt(
            model_id="gen1",
            model_digest=_hex("gen1"),
            corpus_manifest_digest=_hex("corpus-gen1"),
            acquisition_method="licensed",
            timestamp=1000,
            prev_digest="genesis",
        )
        child = build_receipt(
            model_id="gen2",
            model_digest=_hex("gen2"),
            parent_model_digest=root.model_digest,
            corpus_manifest_digest=_hex("corpus-gen2"),
            acquisition_method="consent-gated",
            consent_receipt_ids=("consent-1", "consent-2"),
            timestamp=2000,
            prev_digest=root.receipt_digest,
        )
        grandchild = build_receipt(
            model_id="gen3",
            model_digest=_hex("gen3"),
            parent_model_digest=child.model_digest,
            corpus_manifest_digest=_hex("corpus-gen3"),
            acquisition_method="public-domain",
            timestamp=3000,
            prev_digest=child.receipt_digest,
        )
        return [root, child, grandchild]

    def test_clean_chain_allows(self):
        receipts = self._chain()
        verdicts = verify_lineage(
            receipts, consent_lookup=_consent_db("consent-1", "consent-2").get
        )
        for model_id in ("gen1", "gen2", "gen3"):
            self.assertTrue(verdicts[model_id].allowed, verdicts[model_id].reason)
            self.assertFalse(verdicts[model_id].tainted)

    def test_tainted_parent_propagates(self):
        root = build_receipt(
            model_id="bad-v1",
            model_digest=_hex("bad-v1"),
            corpus_manifest_digest=_hex("corpus-bad"),
            acquisition_method="licensed",
            tainted=True,  # adjudicated infringement
            timestamp=1000,
        )
        child = build_receipt(
            model_id="bad-v2",
            model_digest=_hex("bad-v2"),
            parent_model_digest=root.model_digest,
            corpus_manifest_digest=_hex("corpus-bad-v2"),
            acquisition_method="licensed",
            timestamp=2000,
            prev_digest=root.receipt_digest,
        )
        verdicts = verify_lineage([root, child])
        self.assertFalse(verdicts["bad-v1"].allowed)
        self.assertTrue(verdicts["bad-v1"].tainted)
        self.assertFalse(verdicts["bad-v2"].allowed)
        self.assertTrue(verdicts["bad-v2"].tainted)
        self.assertIn("does not wash", verdicts["bad-v2"].reason)

    def test_taint_transitive_three_generations(self):
        """Laundering: grandchild of a tainted model stays tainted (no washing)."""
        root = build_receipt(
            model_id="l-v1",
            model_digest=_hex("l-v1"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="unknown",  # Bartz: unshowable == pirated
            timestamp=1000,
        )
        mid = build_receipt(
            model_id="l-v2",
            model_digest=_hex("l-v2"),
            parent_model_digest=root.model_digest,
            corpus_manifest_digest=_hex("c2"),
            acquisition_method="licensed",
            timestamp=2000,
            prev_digest=root.receipt_digest,
        )
        leaf = build_receipt(
            model_id="l-v3",
            model_digest=_hex("l-v3"),
            parent_model_digest=mid.model_digest,
            corpus_manifest_digest=_hex("c3"),
            acquisition_method="licensed",
            timestamp=3000,
            prev_digest=mid.receipt_digest,
        )
        verdicts = verify_lineage([root, mid, leaf])
        for model_id in ("l-v1", "l-v2", "l-v3"):
            self.assertFalse(verdicts[model_id].allowed, model_id)
            self.assertTrue(verdicts[model_id].tainted, model_id)

    def test_unknown_acquisition_fail_closes(self):
        r = build_receipt(
            model_id="shady",
            model_digest=_hex("shady"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="unknown",
            timestamp=1000,
        )
        verdicts = verify_lineage([r])
        self.assertFalse(verdicts["shady"].allowed)
        self.assertIn("Bartz", verdicts["shady"].reason)

    def test_lineage_gap_denies(self):
        r = build_receipt(
            model_id="orphan",
            model_digest=_hex("orphan"),
            parent_model_digest=_hex("nonexistent-parent"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="licensed",
            timestamp=1000,
        )
        verdicts = verify_lineage([r])
        self.assertFalse(verdicts["orphan"].allowed)
        self.assertIn("lineage gap", verdicts["orphan"].reason)

    def test_consent_gated_without_receipts_denies(self):
        # Construction allows empty ids only if we bypass build_receipt's
        # guard — but build_receipt permits empty tuple; verification denies.
        r = build_receipt(
            model_id="cg",
            model_digest=_hex("cg"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="consent-gated",
            consent_receipt_ids=(),
            timestamp=1000,
        )
        verdicts = verify_lineage([r], consent_lookup={}.get)
        self.assertFalse(verdicts["cg"].allowed)
        self.assertIn("no consent receipts", verdicts["cg"].reason)

    def test_consent_gated_unresolvable_receipt_denies(self):
        r = build_receipt(
            model_id="cg2",
            model_digest=_hex("cg2"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="consent-gated",
            consent_receipt_ids=("consent-ghost",),
            timestamp=1000,
        )
        verdicts = verify_lineage([r], consent_lookup={}.get)
        self.assertFalse(verdicts["cg2"].allowed)
        self.assertIn("unresolvable", verdicts["cg2"].reason)

    def test_tampered_digest_raises(self):
        import dataclasses

        receipts = self._chain()
        tampered = receipts[1]
        bad = build_receipt(
            model_id=tampered.model_id,
            model_digest=_hex("different-weights"),
            parent_model_digest=tampered.parent_model_digest,
            corpus_manifest_digest=tampered.corpus_manifest_digest,
            acquisition_method=tampered.acquisition_method,
            consent_receipt_ids=tampered.consent_receipt_ids,
            timestamp=tampered.timestamp,
            prev_digest=tampered.prev_digest,
        )
        # Swap the digest to the original's to simulate tampering.
        forged = dataclasses.replace(bad, receipt_digest=tampered.receipt_digest)
        with self.assertRaises(LineageReceiptError):
            verify_lineage([receipts[0], forged, receipts[2]])

    def test_broken_log_chain_raises(self):
        receipts = self._chain()
        with self.assertRaises(LineageReceiptError):
            verify_lineage([receipts[0], receipts[2]])  # skipped middle link

    def test_duplicate_model_digest_raises(self):
        r1 = build_receipt(
            model_id="a",
            model_digest=_hex("same"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="licensed",
            timestamp=1000,
        )
        r2 = build_receipt(
            model_id="b",
            model_digest=_hex("same"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="licensed",
            timestamp=2000,
            prev_digest=r1.receipt_digest,
        )
        with self.assertRaises(LineageReceiptError):
            verify_lineage([r1, r2])


class ClassifyModelTests(unittest.TestCase):
    def test_none_receipt_unverifiable(self):
        self.assertEqual(classify_model(None, []), UNVERIFIABLE_LINEAGE)

    def test_clean_model_verified(self):
        root = build_receipt(
            model_id="ok",
            model_digest=_hex("ok"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="public-domain",
            timestamp=1000,
        )
        self.assertEqual(classify_model(root, [root]), VERIFIED_LINEAGE)

    def test_tainted_model_unverifiable(self):
        root = build_receipt(
            model_id="bad",
            model_digest=_hex("bad"),
            corpus_manifest_digest=_hex("c"),
            acquisition_method="licensed",
            tainted=True,
            timestamp=1000,
        )
        self.assertEqual(classify_model(root, [root]), UNVERIFIABLE_LINEAGE)

    def test_broken_log_unverifiable(self):
        # classify_model must not raise on structural problems.
        self.assertEqual(classify_model(None, []), UNVERIFIABLE_LINEAGE)


if __name__ == "__main__":
    unittest.main()
