"""Tests for editorial.py (one-hundred-seventeenth batch)."""

import unittest

from canonical_json import jcs_sha256_hex

from editorial import (
    AUTHORITATIVE,
    DENY_DISCLOSURE_UNBOUND,
    DENY_EDITOR_IS_PUBLISHER,
    DENY_ELECTION_HOLD,
    DENY_MARKING_STRIPPED,
    DENY_NO_COUNTERSIGN,
    DENY_SLOP_VELOCITY,
    DENY_STALE_REVIEW,
    DENY_UNDISCLOSED_POLITICAL,
    DENY_UNVERIFIABLE_CAPTURE,
    ELECTION_CONTEXT_HOLD,
    NON_AUTHORITATIVE,
    REVIEW_FRESHNESS_WINDOW_S,
    SLOP_VELOCITY_MAX,
    UNVERIFIED_ORIGIN,
    UNVERIFIABLE_CAPTURE,
    CaptureAttestation,
    DisclosureRecord,
    EditorialCountersign,
    EditorRecord,
    EditorRegistry,
    attest_capture,
    check_marking_resilience,
    check_publication,
    compute_countersign_digest,
    countersign_content,
    disclosure_gate,
    editorial_audit_event,
    election_deepfake_check,
    slop_velocity_gate,
    ugc_probe,
)


def _digest(text: str) -> str:
    return jcs_sha256_hex({"payload": text})


def _marking_digest(payload: str) -> str:
    return jcs_sha256_hex({"marking_payload": payload})


class _Fixture:
    """A complete valid editorial setup: editor, registry, disclosure."""

    def __init__(self) -> None:
        self.editor_secret = bytes(range(32))
        self.editor_id = "desk-editor-7"
        self.publisher = "newsbot-agent-3"
        self.publish_time = 1_800_000_000
        self.reviewed_at = self.publish_time - 3_600
        self.content_digest = _digest("breaking-news-draft")
        self.registry = EditorRegistry()
        self.registry.register(
            EditorRecord(
                editor_id=self.editor_id,
                pubkey_hex=self._editor_pubkey(),
                registered_at=self.reviewed_at - 100,
            )
        )
        self.disclosure = DisclosureRecord(
            content_digest=self.content_digest,
            visible_text="This article was drafted with AI assistance and reviewed by a journalist.",
            machine_readable_payload='{"ai_generated": true, "label": "eu-ai-act-art50"}',
            disclosed_at=self.reviewed_at,
        )
        self.countersign = countersign_content(
            content_digest=self.content_digest,
            editor_id=self.editor_id,
            editor_secret=self.editor_secret,
            reviewed_at=self.reviewed_at,
            disclosure_digest=self.disclosure.disclosure_digest,
        )
        self.log = [self.countersign]
        self.marking_payload = "watermark:eu-art50:v1"
        self.marking_digest = _marking_digest(self.marking_payload)

    def _editor_pubkey(self) -> str:
        import ed25519

        return ed25519.public_key(self.editor_secret).hex()

    def publish_kwargs(self, **overrides):
        base = {
            "content_digest": self.content_digest,
            "content_kind": "general",
            "publisher_agent_id": self.publisher,
            "publish_time": self.publish_time,
            "countersign": self.countersign,
            "countersign_log": self.log,
            "registry": self.registry,
            "disclosure": self.disclosure,
            "claims_ai_generated": True,
            "marking_payload": self.marking_payload,
            "expected_marking_digest": self.marking_digest,
            "ugc_capture": False,
            "capture_attestation": None,
            "election_source_attestation": None,
        }
        base.update(overrides)
        return base


class CountersignTest(unittest.TestCase):
    def test_digest_recomputes(self):
        fx = _Fixture()
        self.assertEqual(
            compute_countersign_digest(fx.countersign), fx.countersign.receipt_digest
        )

    def test_happy_path_general_allowed_authoritative(self):
        fx = _Fixture()
        verdict = check_publication(**fx.publish_kwargs())
        self.assertTrue(verdict.allowed, verdict.reason)
        self.assertEqual(verdict.classification, AUTHORITATIVE)
        self.assertEqual(verdict.receipt_digest, fx.countersign.receipt_digest)

    def test_no_countersign_denies_non_authoritative(self):
        fx = _Fixture()
        verdict = check_publication(**fx.publish_kwargs(countersign=None))
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_NO_COUNTERSIGN, verdict.reason)
        self.assertEqual(verdict.classification, NON_AUTHORITATIVE)

    def test_editor_is_publisher_denies(self):
        fx = _Fixture()
        sneaky = countersign_content(
            content_digest=fx.content_digest,
            editor_id=fx.publisher,  # the agent signs as its own "editor"
            editor_secret=bytes(range(32, 64)),
            reviewed_at=fx.reviewed_at,
            disclosure_digest=fx.disclosure.disclosure_digest,
        )
        reg = EditorRegistry()
        import ed25519

        reg.register(
            EditorRecord(
                editor_id=fx.publisher,
                pubkey_hex=ed25519.public_key(bytes(range(32, 64))).hex(),
                registered_at=fx.reviewed_at - 100,
            )
        )
        verdict = check_publication(
            **fx.publish_kwargs(countersign=sneaky, countersign_log=[sneaky], registry=reg)
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_EDITOR_IS_PUBLISHER, verdict.reason)

    def test_revoked_editor_denies(self):
        fx = _Fixture()
        fx.registry.revoke(fx.editor_id, revoked_at=fx.reviewed_at)
        verdict = check_publication(**fx.publish_kwargs())
        self.assertFalse(verdict.allowed)
        self.assertIn("not a registered active editor", verdict.reason)

    def test_stale_review_denies(self):
        fx = _Fixture()
        old = countersign_content(
            content_digest=fx.content_digest,
            editor_id=fx.editor_id,
            editor_secret=fx.editor_secret,
            reviewed_at=fx.publish_time - REVIEW_FRESHNESS_WINDOW_S - 1,
            disclosure_digest=fx.disclosure.disclosure_digest,
        )
        verdict = check_publication(
            **fx.publish_kwargs(countersign=old, countersign_log=[old])
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_STALE_REVIEW, verdict.reason)

    def test_countersign_for_other_content_denies(self):
        fx = _Fixture()
        other = countersign_content(
            content_digest=_digest("some-other-draft"),
            editor_id=fx.editor_id,
            editor_secret=fx.editor_secret,
            reviewed_at=fx.reviewed_at,
            disclosure_digest=fx.disclosure.disclosure_digest,
        )
        verdict = check_publication(
            **fx.publish_kwargs(countersign=other, countersign_log=[other])
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("different content digest", verdict.reason)

    def test_disclosure_swapped_after_review_denies(self):
        fx = _Fixture()
        swapped = DisclosureRecord(
            content_digest=fx.content_digest,
            visible_text="Different disclosure text than reviewed.",
            machine_readable_payload='{"ai_generated": true}',
            disclosed_at=fx.reviewed_at,
        )
        verdict = check_publication(**fx.publish_kwargs(disclosure=swapped))
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_DISCLOSURE_UNBOUND, verdict.reason)

    def test_tampered_log_denies(self):
        fx = _Fixture()
        tampered = EditorialCountersign(
            content_digest=fx.countersign.content_digest,
            editor_id=fx.countersign.editor_id,
            reviewed_at=fx.countersign.reviewed_at,
            disclosure_digest=fx.countersign.disclosure_digest,
            editor_pubkey_hex=fx.countersign.editor_pubkey_hex,
            signature_hex=fx.countersign.signature_hex,
            prev_digest=fx.countersign.prev_digest,
            receipt_digest="ab" * 32,  # wrong digest
        )
        verdict = check_publication(**fx.publish_kwargs(countersign_log=[tampered]))
        self.assertFalse(verdict.allowed)
        self.assertIn("integrity failure", verdict.reason)

    def test_unknown_receipt_denies(self):
        fx = _Fixture()
        other = countersign_content(
            content_digest=fx.content_digest,
            editor_id=fx.editor_id,
            editor_secret=fx.editor_secret,
            reviewed_at=fx.reviewed_at + 60,  # distinct digest: not in fx.log
            disclosure_digest=fx.disclosure.disclosure_digest,
        )
        # other is NOT in fx.log
        verdict = check_publication(**fx.publish_kwargs(countersign=other))
        self.assertFalse(verdict.allowed)
        self.assertIn("not present in the countersign log", verdict.reason)


class DisclosureGateTest(unittest.TestCase):
    def test_political_without_disclosure_hard_denies(self):
        verdict = disclosure_gate(
            content_kind="political",
            disclosure=None,
            content_digest=_digest("ad-copy"),
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_UNDISCLOSED_POLITICAL, verdict.reason)

    def test_election_without_disclosure_hard_denies(self):
        verdict = disclosure_gate(
            content_kind="election",
            disclosure=None,
            content_digest=_digest("ad-copy"),
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_UNDISCLOSED_POLITICAL, verdict.reason)

    def test_political_with_bound_disclosure_passes_gate(self):
        digest = _digest("ad-copy")
        disclosure = DisclosureRecord(
            content_digest=digest,
            visible_text="AI-generated political advertisement.",
            machine_readable_payload='{"ai_generated": true}',
            disclosed_at=1,
        )
        verdict = disclosure_gate(
            content_kind="political", disclosure=disclosure, content_digest=digest
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, AUTHORITATIVE)

    def test_general_without_disclosure_allows_non_authoritative(self):
        verdict = disclosure_gate(
            content_kind="general", disclosure=None, content_digest=_digest("x")
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, NON_AUTHORITATIVE)

    def test_disclosure_bound_to_other_content_denies(self):
        disclosure = DisclosureRecord(
            content_digest=_digest("other"),
            visible_text="AI-generated.",
            machine_readable_payload='{"ai_generated": true}',
            disclosed_at=1,
        )
        verdict = disclosure_gate(
            content_kind="general",
            disclosure=disclosure,
            content_digest=_digest("actual"),
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_DISCLOSURE_UNBOUND, verdict.reason)


class MarkingResilienceTest(unittest.TestCase):
    def test_verified_marking_passes(self):
        verdict = check_marking_resilience(
            claims_ai_generated=True,
            marking_payload="wm:v1",
            expected_marking_digest=_marking_digest("wm:v1"),
        )
        self.assertTrue(verdict.allowed)

    def test_missing_marking_denies_unverified_origin(self):
        verdict = check_marking_resilience(
            claims_ai_generated=True,
            marking_payload=None,
            expected_marking_digest=None,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_MARKING_STRIPPED, verdict.reason)
        self.assertEqual(verdict.classification, UNVERIFIED_ORIGIN)

    def test_downgraded_marking_denies(self):
        verdict = check_marking_resilience(
            claims_ai_generated=True,
            marking_payload="tampered",
            expected_marking_digest=_marking_digest("wm:v1"),
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_MARKING_STRIPPED, verdict.reason)

    def test_no_ai_claim_skips_gate(self):
        verdict = check_marking_resilience(
            claims_ai_generated=False,
            marking_payload=None,
            expected_marking_digest=None,
        )
        self.assertTrue(verdict.allowed)


class UgcProbeTest(unittest.TestCase):
    def _attestation(self, capture_digest: str) -> CaptureAttestation:
        return attest_capture(
            capture_digest=capture_digest,
            attestor_id="pixel-11-camera",
            attestor_secret=bytes(range(64, 96)),
            captured_at=1_799_000_000,
        )

    def test_ugc_without_attestation_denies(self):
        verdict = ugc_probe(capture_digest=_digest("clip"), attestation=None)
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_UNVERIFIABLE_CAPTURE, verdict.reason)
        self.assertEqual(verdict.classification, UNVERIFIABLE_CAPTURE)

    def test_ugc_with_valid_attestation_allows(self):
        digest = _digest("clip")
        verdict = ugc_probe(
            capture_digest=digest, attestation=self._attestation(digest)
        )
        self.assertTrue(verdict.allowed)

    def test_ugc_attestation_for_other_capture_denies(self):
        verdict = ugc_probe(
            capture_digest=_digest("clip-a"),
            attestation=self._attestation(_digest("clip-b")),
        )
        self.assertFalse(verdict.allowed)

    def test_full_publication_with_ugc_path(self):
        fx = _Fixture()
        digest = _digest("ugc-story")
        fx2 = _Fixture()
        # rebuild fixture around the UGC digest for a coherent chain
        att = self._attestation(digest)
        disclosure = DisclosureRecord(
            content_digest=digest,
            visible_text="UGC republication; AI-assisted edit, reviewed.",
            machine_readable_payload='{"ai_generated": true, "ugc": true}',
            disclosed_at=fx2.reviewed_at,
        )
        cs = countersign_content(
            content_digest=digest,
            editor_id=fx2.editor_id,
            editor_secret=fx2.editor_secret,
            reviewed_at=fx2.reviewed_at,
            disclosure_digest=disclosure.disclosure_digest,
        )
        verdict = check_publication(
            content_digest=digest,
            content_kind="general",
            publisher_agent_id=fx2.publisher,
            publish_time=fx2.publish_time,
            countersign=cs,
            countersign_log=[cs],
            registry=fx2.registry,
            disclosure=disclosure,
            claims_ai_generated=True,
            marking_payload=fx2.marking_payload,
            expected_marking_digest=fx2.marking_digest,
            ugc_capture=True,
            capture_attestation=att,
        )
        self.assertTrue(verdict.allowed, verdict.reason)


class ElectionHoldTest(unittest.TestCase):
    def _attestation(self) -> CaptureAttestation:
        return attest_capture(
            capture_digest=_digest("rally-clip"),
            attestor_id="newsroom-ingest",
            attestor_secret=bytes(range(96, 128)),
            captured_at=1_799_000_000,
        )

    def test_election_missing_review_holds(self):
        verdict = election_deepfake_check(
            content_kind="election",
            source_attestation=self._attestation(),
            human_review=None,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_ELECTION_HOLD, verdict.reason)
        self.assertEqual(verdict.classification, ELECTION_CONTEXT_HOLD)

    def test_election_missing_attestation_holds(self):
        fx = _Fixture()
        verdict = election_deepfake_check(
            content_kind="election",
            source_attestation=None,
            human_review=fx.countersign,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_ELECTION_HOLD, verdict.reason)

    def test_election_with_both_allows(self):
        fx = _Fixture()
        verdict = election_deepfake_check(
            content_kind="election",
            source_attestation=self._attestation(),
            human_review=fx.countersign,
        )
        self.assertTrue(verdict.allowed)

    def test_full_election_publication(self):
        fx = _Fixture()
        digest = _digest("election-story")
        att = attest_capture(
            capture_digest=digest,
            attestor_id="newsroom-ingest",
            attestor_secret=bytes(range(96, 128)),
            captured_at=fx.reviewed_at,
        )
        disclosure = DisclosureRecord(
            content_digest=digest,
            visible_text="AI-generated election coverage; human-reviewed.",
            machine_readable_payload='{"ai_generated": true, "election": true}',
            disclosed_at=fx.reviewed_at,
        )
        cs = countersign_content(
            content_digest=digest,
            editor_id=fx.editor_id,
            editor_secret=fx.editor_secret,
            reviewed_at=fx.reviewed_at,
            disclosure_digest=disclosure.disclosure_digest,
        )
        verdict = check_publication(
            content_digest=digest,
            content_kind="election",
            publisher_agent_id=fx.publisher,
            publish_time=fx.publish_time,
            countersign=cs,
            countersign_log=[cs],
            registry=fx.registry,
            disclosure=disclosure,
            claims_ai_generated=True,
            marking_payload=fx.marking_payload,
            expected_marking_digest=fx.marking_digest,
            election_source_attestation=att,
        )
        self.assertTrue(verdict.allowed, verdict.reason)
        self.assertEqual(verdict.classification, AUTHORITATIVE)


class SlopVelocityTest(unittest.TestCase):
    def test_over_velocity_denies(self):
        verdict = slop_velocity_gate(
            source_id="slop-farm-1",
            publish_times=list(range(1_800_000_000, 1_800_000_000 + SLOP_VELOCITY_MAX + 1)),
            window_start=1_800_000_000,
            window_end=1_800_003_600,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_SLOP_VELOCITY, verdict.reason)

    def test_at_velocity_allows(self):
        verdict = slop_velocity_gate(
            source_id="steady-desk-2",
            publish_times=list(range(1_800_000_000, 1_800_000_000 + SLOP_VELOCITY_MAX)),
            window_start=1_800_000_000,
            window_end=1_800_003_600,
        )
        self.assertTrue(verdict.allowed)

    def test_outside_window_not_counted(self):
        verdict = slop_velocity_gate(
            source_id="steady-desk-3",
            publish_times=[1_700_000_000] * (SLOP_VELOCITY_MAX + 50),
            window_start=1_800_000_000,
            window_end=1_800_003_600,
        )
        self.assertTrue(verdict.allowed)


class AuditEventTest(unittest.TestCase):
    def test_audit_event_shape(self):
        fx = _Fixture()
        verdict = check_publication(**fx.publish_kwargs())
        event = editorial_audit_event(verdict, action="publish")
        self.assertEqual(event["event"], "editorial.allowed")
        self.assertTrue(event["allowed"])
        self.assertEqual(event["classification"], AUTHORITATIVE)
        denied = check_publication(**fx.publish_kwargs(countersign=None))
        event2 = editorial_audit_event(denied, action="publish")
        self.assertEqual(event2["event"], "editorial.denied")


if __name__ == "__main__":
    unittest.main()
