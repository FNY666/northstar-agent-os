"""Tests for newsmedia_agents (one-hundred-fifty-eighth batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519

import newsmedia_agents as nm


T0 = 1_800_000_000
SEC = b"nm-test-auth-" + b"7" * 19  # 32 bytes
assert len(SEC) == 32
SEC2 = b"nm-test-auth-" + b"8" * 19
assert len(SEC2) == 32
PUB = ed25519.public_key(SEC).hex()
HEX64 = "ab" * 32
HEX64_B = "cd" * 32


def _tip(log):
    return log._log[-1].receipt_digest if log._log else nm._GENESIS


def _src_log(story="s1", involvement=nm.AI_ASSISTED, expires_at=T0 + 86400):
    log = nm.SourceLog()
    log.append(
        nm.source_receipt(
            receipt_id="r1", story_id=story, issuer_id="op-1",
            issuer_pubkey_hex=PUB, ai_involvement=involvement,
            expires_at=expires_at, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _mat_log(published_at=T0, materiality=nm.MATERIAL, disclosed_at=None):
    log = nm.MaterialityLog()
    log.append(
        nm.materiality_receipt(
            receipt_id="m1", story_id="s1", materiality=materiality,
            published_at=published_at, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    if disclosed_at is not None:
        log.append(
            nm.disclosure_receipt(
                receipt_id="d1", story_id="s1", disclosed_at=disclosed_at,
                disclosure_format="inline_banner", placement_digest=HEX64,
                authority_pubkey_hex=PUB, authority_secret=SEC,
                prev_digest=_tip(log),
            )
        )
    return log


def _cit_registry():
    reg = nm.CitationRegistry()
    reg.register(
        nm.CitationRecord(
            record_id="c1", claim_id="claim1", cited_outlet_id="wire",
            cited_url_digest=HEX64, resolved=True, resolution_note="ok",
        )
    )
    return reg


def _vlog(claim="claim1", tier=nm.TIER_MEDIUM, depth=2, digests=(HEX64,)):
    log = nm.VerificationLog()
    log.append(
        nm.verification_receipt(
            receipt_id="v1", claim_id=claim, story_id="s1", claim_tier=tier,
            verification_depth=depth, source_digests=list(digests),
            verified_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _media_log(media="m1", kind=nm.KIND_VIDEO, authentic=True, ai_generated=False):
    log = nm.MediaScreenLog()
    log.append(
        nm.media_screen_receipt(
            receipt_id="ms1", media_id=media, story_id="s1", media_kind=kind,
            external=True, ai_generated=ai_generated, screening_method="c2pa",
            authentic=authentic, screened_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _byline_log(story="s1", verified=True, name="Ada Reporter"):
    log = nm.BylineLog()
    log.append(
        nm.byline_receipt(
            receipt_id="b1", story_id=story, byline_name=name,
            human_verified=verified, identity_digest=HEX64,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _license_log(corpus="corp1", source=nm.LIC_LICENSED):
    log = nm.LicenseLog()
    log.append(
        nm.license_chain_receipt(
            receipt_id="l1", corpus_id=corpus, license_source=source,
            chain_digest=HEX64, checked_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _pipeline_log(baseline=100, current=95):
    log = nm.PipelineLog()
    log.append(
        nm.pipeline_clock_receipt(
            receipt_id="p1", newsroom_id="n1", baseline_junior=baseline,
            current_junior=current, reviewed_at=T0, next_review_due=T0 + 86400 * 90,
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _probe_log(fmt="inline_banner", comprehension=5000):
    log = nm.ProbeLog()
    log.append(
        nm.disclosure_probe_receipt(
            receipt_id="dp1", format_id=fmt, comprehension_bps=comprehension,
            trust_delta_bps=-200, probed_at=T0, authority_pubkey_hex=PUB,
            authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


def _freeze_log(start=T0, end=T0 + 86400 * 90, covered=(nm.TIER_ELECTION,)):
    log = nm.FreezeLog()
    log.append(
        nm.election_source_freeze(
            receipt_id="e1", election_id="midterms", freeze_start=start,
            freeze_end=end, covered_tiers=list(covered),
            authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=nm._GENESIS,
        )
    )
    return log


class NewsmediaAgentsTest(unittest.TestCase):
    # --- attribution ------------------------------------------------------

    def test_attribution_allows_live_issuer_receipt(self):
        v = nm.check_attribution(story_id="s1", log=_src_log(), checked_at=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, nm.CLASS_AUTHORITATIVE)

    def test_attribution_denies_anonymous_ai_story(self):
        v = nm.check_attribution(story_id="ghost", log=_src_log(), checked_at=T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.unattributed"))

    def test_attribution_denies_expired_identity(self):
        log = _src_log(expires_at=T0 - 1)
        v = nm.check_attribution(story_id="s1", log=log, checked_at=T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.unattributed"))

    def test_source_receipt_rejects_secret_mismatch(self):
        with self.assertRaises(nm.NewsmediaError):
            nm.source_receipt(
                receipt_id="r9", story_id="s9", issuer_id="op-1",
                issuer_pubkey_hex=PUB, ai_involvement=nm.AI_GENERATED,
                expires_at=T0 + 100, authority_pubkey_hex=PUB,
                authority_secret=SEC2, prev_digest=nm._GENESIS,
            )

    def test_source_log_rejects_chain_break(self):
        log = nm.SourceLog()
        log.append(
            nm.source_receipt(
                receipt_id="r1", story_id="s1", issuer_id="op-1",
                issuer_pubkey_hex=PUB, ai_involvement=nm.AI_HUMAN,
                expires_at=T0 + 100, authority_pubkey_hex=PUB,
                authority_secret=SEC, prev_digest=nm._GENESIS,
            )
        )
        with self.assertRaises(nm.NewsmediaError):
            log.append(
                nm.source_receipt(
                    receipt_id="r2", story_id="s2", issuer_id="op-1",
                    issuer_pubkey_hex=PUB, ai_involvement=nm.AI_HUMAN,
                    expires_at=T0 + 100, authority_pubkey_hex=PUB,
                    authority_secret=SEC, prev_digest="wrong",
                )
            )

    # --- materiality disclosure clock -------------------------------------

    def test_material_disclosure_within_window_allows(self):
        v = nm.materiality_disclosure_clock(
            story_id="s1", log=_mat_log(disclosed_at=T0 + 3600), checked_at=T0 + 4000
        )
        self.assertTrue(v.allowed)

    def test_material_disclosure_past_deadline_denies(self):
        v = nm.materiality_disclosure_clock(
            story_id="s1", log=_mat_log(disclosed_at=T0 + 200_000), checked_at=T0 + 200_001
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.undisclosed_material_use"))

    def test_material_no_disclosure_denies(self):
        v = nm.materiality_disclosure_clock(
            story_id="s1", log=_mat_log(disclosed_at=None), checked_at=T0 + 4000
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.undisclosed_material_use"))

    def test_ungraded_materiality_denies(self):
        v = nm.materiality_disclosure_clock(
            story_id="ghost", log=_mat_log(), checked_at=T0 + 4000
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.ungraded_materiality"))

    def test_non_material_needs_no_disclosure(self):
        v = nm.materiality_disclosure_clock(
            story_id="s1", log=_mat_log(materiality=nm.NON_MATERIAL), checked_at=T0 + 4000
        )
        self.assertTrue(v.allowed)

    # --- verification depth + citation integrity ---------------------------

    def test_verification_depth_allows_meeting_tier(self):
        v = nm.verification_depth_gate(claim_id="claim1", vlog=_vlog(), citations=_cit_registry())
        self.assertTrue(v.allowed)

    def test_verification_depth_denies_shallow(self):
        v = nm.verification_depth_gate(
            claim_id="claim1", vlog=_vlog(tier=nm.TIER_HIGH, depth=1),
            citations=_cit_registry(),
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.citation_failure"))

    def test_verification_depth_denies_unresolvable_source(self):
        v = nm.verification_depth_gate(
            claim_id="claim1", vlog=_vlog(digests=(HEX64_B,)), citations=_cit_registry()
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.citation_failure"))

    def test_citation_integrity_denies_fabricated(self):
        reg = nm.CitationRegistry()
        reg.register(
            nm.CitationRecord(
                record_id="c2", claim_id="ghost", cited_outlet_id="iwate-nippo",
                cited_url_digest=HEX64_B, resolved=False, resolution_note="denied",
            )
        )
        v = nm.citation_integrity_gate(claim_id="ghost", citations=reg)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.fabricated_citation"))

    def test_citation_integrity_allows_resolved(self):
        v = nm.citation_integrity_gate(claim_id="claim1", citations=_cit_registry())
        self.assertTrue(v.allowed)

    # --- media screening + photo ban --------------------------------------

    def test_external_media_screened_authentic_allows(self):
        v = nm.external_media_screen(media_id="m1", external=True, log=_media_log())
        self.assertTrue(v.allowed)

    def test_external_media_unscreened_denies(self):
        v = nm.external_media_screen(media_id="ghost", external=True, log=_media_log())
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.unsourced_visual"))

    def test_external_media_inauthentic_denies(self):
        v = nm.external_media_screen(
            media_id="m1", external=True, log=_media_log(authentic=False)
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.unsourced_visual"))

    def test_newsroom_produced_media_skips_screening(self):
        v = nm.external_media_screen(media_id="m1", external=False, log=nm.MediaScreenLog())
        self.assertTrue(v.allowed)

    def test_photo_integrity_ban_refuses_ai_news_photo(self):
        v = nm.check_photo_integrity(
            media_id="m1", log=_media_log(kind=nm.KIND_PHOTO, ai_generated=True)
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.photo_generation_refused"))

    def test_photo_integrity_allows_real_photo(self):
        v = nm.check_photo_integrity(media_id="m1", log=_media_log(kind=nm.KIND_PHOTO))
        self.assertTrue(v.allowed)

    # --- funding / byline / license ---------------------------------------

    def test_funding_disclosure_allows_disclosed_outlet(self):
        log = nm.FundingLog()
        log.append(
            nm.funding_disclosure_receipt(
                receipt_id="f1", outlet_id="o1", funders=["trust-a"],
                partisan_alignment="center", disclosed_at=T0,
                authority_pubkey_hex=PUB, authority_secret=SEC, prev_digest=nm._GENESIS,
            )
        )
        v = nm.political_funding_disclosure(outlet_id="o1", log=log)
        self.assertTrue(v.allowed)

    def test_funding_disclosure_denies_pink_slime(self):
        v = nm.political_funding_disclosure(outlet_id="pink-slime", log=nm.FundingLog())
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.funding_undisclosed"))

    def test_byline_allows_verified_human(self):
        v = nm.byline_verification(story_id="s1", log=_byline_log())
        self.assertTrue(v.allowed)

    def test_byline_denies_fictional(self):
        v = nm.byline_verification(
            story_id="s1", log=_byline_log(verified=False, name="Dr. X NASA Engineer")
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.fictional_byline"))

    def test_license_allows_clean_chain(self):
        v = nm.check_license_chain(corpus_id="corp1", log=_license_log())
        self.assertTrue(v.allowed)

    def test_license_denies_pirated_chain(self):
        v = nm.check_license_chain(corpus_id="corp1", log=_license_log(source=nm.LIC_PIRATED))
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.illegitimate_source"))

    def test_license_denies_missing_chain(self):
        v = nm.check_license_chain(corpus_id="corp1", log=nm.LicenseLog())
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.illegitimate_source"))

    # --- pipeline clock / disclosure probe / election freeze --------------

    def test_pipeline_clock_allows_within_tolerance(self):
        v = nm.newsroom_job_pipeline_clock(newsroom_id="n1", log=_pipeline_log())
        self.assertTrue(v.allowed)

    def test_pipeline_clock_denies_above_tolerance(self):
        v = nm.newsroom_job_pipeline_clock(newsroom_id="n1", log=_pipeline_log(current=60))
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.pipeline_review"))

    def test_disclosure_probe_allows_clearing_format(self):
        v = nm.disclosure_effectiveness_probe(format_id="inline_banner", log=_probe_log())
        self.assertTrue(v.allowed)

    def test_disclosure_probe_denies_below_floor(self):
        v = nm.disclosure_effectiveness_probe(
            format_id="inline_banner", log=_probe_log(comprehension=1000)
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.disclosure_ineffective"))

    def test_election_freeze_allows_outside_window(self):
        v = nm.check_election_freeze(
            election_id="midterms", claim_id="c1", claim_tier=nm.TIER_ELECTION,
            claim_ts=T0 + 86400 * 100, log=_freeze_log(),
        )
        self.assertTrue(v.allowed)

    def test_election_freeze_denies_covered_claim_without_override(self):
        v = nm.check_election_freeze(
            election_id="midterms", claim_id="c1", claim_tier=nm.TIER_ELECTION,
            claim_ts=T0 + 1000, log=_freeze_log(),
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("newsmedia.freeze_violation"))

    def test_election_freeze_allows_override(self):
        log = _freeze_log()
        log.append(
            nm.election_override_receipt(
                receipt_id="eo1", election_id="midterms", claim_id="c1",
                override_reason="verified public-record correction",
                authority_pubkey_hex=PUB, authority_secret=SEC,
                prev_digest=_tip(log),
            )
        )
        v = nm.check_election_freeze(
            election_id="midterms", claim_id="c1", claim_tier=nm.TIER_ELECTION,
            claim_ts=T0 + 1000, log=log,
        )
        self.assertTrue(v.allowed)

    def test_election_freeze_skips_uncovered_tier(self):
        v = nm.check_election_freeze(
            election_id="midterms", claim_id="c1", claim_tier=nm.TIER_LOW,
            claim_ts=T0 + 1000, log=_freeze_log(covered=(nm.TIER_ELECTION,)),
        )
        self.assertTrue(v.allowed)

    # --- audit events ------------------------------------------------------

    def test_audit_event_shape(self):
        v = nm.check_attribution(story_id="s1", log=_src_log(), checked_at=T0)
        event = nm.newsmedia_audit_event(v, action="publish")
        self.assertEqual(event["action"], "publish")
        self.assertTrue(event["verdict_allowed"])
        self.assertEqual(event["schema_version"], nm.NEWSMEDIA_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
