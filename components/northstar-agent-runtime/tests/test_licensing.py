"""Tests for licensing.py (one-hundred-twentieth batch)."""

import unittest

from licensing import (
    DENY_AI_ONLY,
    DENY_BAD_SPLIT,
    DENY_LAUNDERED,
    DENY_LIKENESS_THEFT,
    DENY_LINEAGE_GAP,
    DENY_TIER_FRAUD,
    DENY_UNKNOWN_TAKE,
    DENY_UNLABELED_AI_PARTS,
    DENY_UNLICENSED_CORPUS,
    LicensingError,
    check_likeness_use,
    check_performer_tier,
    check_split_terms,
    check_take,
    check_training_receipt,
    human_contribution_gate,
    issue_likeness_grant,
    issue_performer_disclosure,
    issue_take_receipt,
    issue_work_contribution,
    licensed_training_receipt,
    split_terms,
    verify_derivation_sources,
)


T0 = 1_700_000_000
AUTHORITY = bytes(range(32))
HOLDER = bytes([9]) * 32
OTHER = bytes([5]) * 32
CORPUS = "aa" * 32
PROOF_A = "bb" * 32
PROOF_B = "cc" * 32


def _proof_digest(pairs):
    from canonical_json import jcs_sha256_hex

    return jcs_sha256_hex(sorted(pairs))


def _split_terms(prev="genesis"):
    return split_terms(
        terms_id="terms-1",
        publishing_share_bps=5000,
        masters_share_bps=5000,
        effective_from=T0,
        authority_secret=AUTHORITY,
        issued_by="nmpa-style-authority",
        prev_digest=prev,
    )


def _training_receipt(prev="genesis", **over):
    terms = _split_terms()
    proof_digest = _proof_digest(
        [("warner-records", PROOF_A), ("merlin-indies", PROOF_B)]
    )
    kw = dict(
        receipt_id="ltr-1",
        model_id="suno-style-v6",
        corpus_digest=CORPUS,
        licensor_ids=("warner-records", "merlin-indies"),
        opt_in_proof_digest=proof_digest,
        split_terms_digest=terms.receipt_digest,
        authority_secret=AUTHORITY,
        issued_by="licensing-authority",
        issued_at=T0,
        expires_at=T0 + 86_400,
        prev_digest=prev,
    )
    kw.update(over)
    return licensed_training_receipt(**kw)


def _lookup(proofs):
    def _fn(licensor_id):
        return proofs.get(licensor_id)

    return _fn


class LicensedTrainingTest(unittest.TestCase):
    def test_allow_fully_licensed(self):
        receipt = _training_receipt()
        v = check_training_receipt(
            [receipt],
            model_id="suno-style-v6",
            corpus_digest=CORPUS,
            opt_in_lookup=_lookup(
                {"warner-records": PROOF_A, "merlin-indies": PROOF_B}
            ),
            check_time=T0 + 60,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_deny_no_receipt(self):
        v = check_training_receipt(
            [],
            model_id="suno-style-v6",
            corpus_digest=CORPUS,
            opt_in_lookup=_lookup({}),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNLICENSED_CORPUS, v.reason)

    def test_deny_missing_opt_in(self):
        receipt = _training_receipt()
        v = check_training_receipt(
            [receipt],
            model_id="suno-style-v6",
            corpus_digest=CORPUS,
            opt_in_lookup=_lookup({"warner-records": PROOF_A}),  # merlin missing
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNLICENSED_CORPUS, v.reason)
        self.assertIn("merlin-indies", v.reason)

    def test_deny_corpus_digest_mismatch(self):
        receipt = _training_receipt()
        v = check_training_receipt(
            [receipt],
            model_id="suno-style-v6",
            corpus_digest="dd" * 32,
            opt_in_lookup=_lookup(
                {"warner-records": PROOF_A, "merlin-indies": PROOF_B}
            ),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertIn("digest mismatch", v.reason)

    def test_deny_expired_receipt(self):
        receipt = _training_receipt()
        v = check_training_receipt(
            [receipt],
            model_id="suno-style-v6",
            corpus_digest=CORPUS,
            opt_in_lookup=_lookup(
                {"warner-records": PROOF_A, "merlin-indies": PROOF_B}
            ),
            check_time=T0 + 86_401,
        )
        self.assertFalse(v.allowed)

    def test_issue_empty_licensors_raises(self):
        with self.assertRaises(LicensingError):
            _training_receipt(licensor_ids=())


class LaunderingTest(unittest.TestCase):
    def test_allow_clean_derivation(self):
        v = verify_derivation_sources(
            derivation_sources=("ab" * 32,),
            lineage_lookup=lambda d: {"tainted": False},
        )
        self.assertTrue(v.allowed)

    def test_deny_tainted_source(self):
        v = verify_derivation_sources(
            derivation_sources=("ab" * 32,),
            lineage_lookup=lambda d: {"tainted": True},
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LAUNDERED, v.reason)

    def test_deny_lineage_gap(self):
        v = verify_derivation_sources(
            derivation_sources=("ab" * 32,),
            lineage_lookup=lambda d: None,
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LINEAGE_GAP, v.reason)

    def test_deny_no_lookup(self):
        v = verify_derivation_sources(derivation_sources=("ab" * 32,))
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LINEAGE_GAP, v.reason)


class SplitTermsTest(unittest.TestCase):
    def test_allow_pinned_terms(self):
        terms = _split_terms()
        v = check_split_terms([terms], terms_id="terms-1", terms_digest=terms.receipt_digest)
        self.assertTrue(v.allowed)
        self.assertIn("5000", v.reason)

    def test_issue_non_summing_raises(self):
        with self.assertRaises(LicensingError):
            split_terms(
                terms_id="bad",
                publishing_share_bps=6000,
                masters_share_bps=5000,
                effective_from=T0,
                authority_secret=AUTHORITY,
                issued_by="x",
            )

    def test_deny_terms_digest_changed(self):
        terms = _split_terms()
        v = check_split_terms([terms], terms_id="terms-1", terms_digest="ff" * 32)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_BAD_SPLIT, v.reason)


class ContributionTest(unittest.TestCase):
    def _issue(self, cls, labeled=True):
        return issue_work_contribution(
            receipt_id="wc-1",
            work_digest="ee" * 32,
            contribution_class=cls,
            ai_parts_labeled=labeled,
            authority_secret=AUTHORITY,
            declared_by="rights-office",
            declared_at=T0,
        )

    def test_allow_human_authored(self):
        v = human_contribution_gate([self._issue("human-authored")], work_digest="ee" * 32)
        self.assertTrue(v.allowed)

    def test_allow_ai_assisted_labeled(self):
        v = human_contribution_gate(
            [self._issue("ai-assisted", labeled=True)], work_digest="ee" * 32
        )
        self.assertTrue(v.allowed)

    def test_deny_ai_only(self):
        v = human_contribution_gate([self._issue("ai-only")], work_digest="ee" * 32)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_AI_ONLY, v.reason)
        self.assertEqual(v.classification, DENY_AI_ONLY)

    def test_deny_unlabeled_ai_parts(self):
        v = human_contribution_gate(
            [self._issue("ai-assisted", labeled=False)], work_digest="ee" * 32
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNLABELED_AI_PARTS, v.reason)

    def test_deny_no_declaration(self):
        v = human_contribution_gate([], work_digest="ee" * 32)
        self.assertFalse(v.allowed)


class PerformerTierTest(unittest.TestCase):
    def _issue(self, declared, evidence):
        return issue_performer_disclosure(
            receipt_id="pd-1",
            performer_id="plave-style",
            declared_tier=declared,
            evidence_tier=evidence,
            authority_secret=AUTHORITY,
            issued_by="label",
            issued_at=T0,
        )

    def test_allow_honest_tier(self):
        v = check_performer_tier(
            [self._issue("mocap-assisted-real", "mocap-assisted-real")],
            performer_id="plave-style",
        )
        self.assertTrue(v.allowed)

    def test_deny_tier_fraud(self):
        v = check_performer_tier(
            [self._issue("mocap-assisted-real", "full-synthetic")],
            performer_id="plave-style",
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_TIER_FRAUD, v.reason)

    def test_deny_no_receipt(self):
        v = check_performer_tier([], performer_id="ghost")
        self.assertFalse(v.allowed)


class LikenessTest(unittest.TestCase):
    def _grant(self, scopes=("music-video",), **over):
        kw = dict(
            grant_id="lg-1",
            likeness_digest="11" * 32,
            holder_id="artist-7",
            scopes=scopes,
            holder_secret=HOLDER,
            granted_at=T0,
            expires_at=T0 + 86_400,
        )
        kw.update(over)
        return issue_likeness_grant(**kw)

    def test_allow_covered_scope(self):
        v = check_likeness_use(
            [self._grant()], likeness_digest="11" * 32, use_scope="music-video", check_time=T0 + 60
        )
        self.assertTrue(v.allowed)

    def test_deny_scope_outside_grant(self):
        v = check_likeness_use(
            [self._grant()], likeness_digest="11" * 32, use_scope="advertising", check_time=T0 + 60
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LIKENESS_THEFT, v.reason)

    def test_deny_no_grant(self):
        v = check_likeness_use(
            [], likeness_digest="11" * 32, use_scope="music-video", check_time=T0 + 60
        )
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LIKENESS_THEFT, v.reason)

    def test_deny_expired_grant(self):
        v = check_likeness_use(
            [self._grant()], likeness_digest="11" * 32, use_scope="music-video", check_time=T0 + 86_401
        )
        self.assertFalse(v.allowed)


class TakeTest(unittest.TestCase):
    def _take(self):
        return issue_take_receipt(
            take_id="take-42",
            model_version="cineme-previz-v3",
            prompt_digest="22" * 32,
            assets_digest="33" * 32,
            rights_review_digest="44" * 32,
            authority_secret=AUTHORITY,
            issued_by="production",
            issued_at=T0,
        )

    def test_allow_sealed_take(self):
        v = check_take([self._take()], take_id="take-42")
        self.assertTrue(v.allowed)

    def test_deny_unknown_take(self):
        v = check_take([self._take()], take_id="take-43")
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNKNOWN_TAKE, v.reason)


class ChainIntegrityTest(unittest.TestCase):
    def test_tampered_receipt_denies(self):
        receipt = _training_receipt()
        tampered = type(receipt)(
            **{**receipt.__dict__, "model_id": "forged-model"}
        )
        v = check_training_receipt(
            [tampered],
            model_id="forged-model",
            corpus_digest=CORPUS,
            opt_in_lookup=_lookup({}),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertIn("integrity failure", v.reason)

    def test_tampered_proof_bundle_denies(self):
        receipt = _training_receipt()
        v = check_training_receipt(
            [receipt],
            model_id="suno-style-v6",
            corpus_digest=CORPUS,
            opt_in_lookup=_lookup(
                {"warner-records": "99" * 32, "merlin-indies": PROOF_B}
            ),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertIn("does not recompute", v.reason)


if __name__ == "__main__":
    unittest.main()
