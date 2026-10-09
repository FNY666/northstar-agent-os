"""Tests for adtech_agents.py (one-hundred-forty-ninth batch)."""

import unittest

import ed25519

import adtech_agents
from adtech_agents import (
    AdtechError,
    BriefLog,
    DarkPatternLog,
    FatigueLog,
    LiabilityLog,
    MaterialityLog,
    MatrixLog,
    PerformerLog,
    WatermarkLog,
    DARK_PATTERN_CATALOG,
    MIN_COMPREHENSION_BPS,
    MAX_EXPOSURES_PER_FORMAT,
    agentic_brief_binding,
    check_interface,
    check_machine_reading,
    check_matrix_pin,
    check_objective_drift,
    check_performer_disclosure,
    check_platform_liability,
    dark_pattern_screen,
    jurisdiction_matrix_digest,
    jurisdiction_matrix_pin,
    label_fatigue_guard,
    label_fatigue_sample,
    machine_readable_marking,
    materiality_assessment_receipt,
    materiality_label_clock,
    platform_liability_pin,
    synthetic_performer_receipt,
    testimonial_existence_gate,
)

# The imported gate's name starts with "test", so pytest would collect the
# production function itself as a test item (and fail on its parameters as
# missing fixtures). It is a helper under test, not a test.
testimonial_existence_gate.__test__ = False

_SEED = bytes(range(32))
_PUBKEY = ed25519.public_key(_SEED).hex()
_T0 = 1_800_000_000
_T1 = 1_800_003_600


class _Base(unittest.TestCase):
    def hex(self, c: str) -> str:
        return c * 64

    def prev(self, log) -> str:
        return log._log[-1].receipt_digest if log._log else "genesis"


class TestPerformerReceipts(_Base):
    def _bind(self, log, performer_id="perf-1", **kw):
        args = dict(
            receipt_id="pr-1",
            performer_id=performer_id,
            identity_binding_digest=self.hex("a"),
            consent_record_digest=self.hex("b"),
            disclosure_receipt_digest=self.hex("c"),
            expires_at=_T1,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(synthetic_performer_receipt(**args))
        return args

    def test_bound_performer_allowed(self):
        log = PerformerLog()
        self._bind(log)
        log.verify()
        verdict = check_performer_disclosure(log=log, performer_id="perf-1", now=_T0)
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.receipt_digest)

    def test_unbound_performer_denied(self):
        log = PerformerLog()
        verdict = check_performer_disclosure(log=log, performer_id="ghost", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_performer_identity", verdict.reason)

    def test_expired_binding_denied(self):
        log = PerformerLog()
        self._bind(log, expires_at=_T0 - 1)
        verdict = check_performer_disclosure(log=log, performer_id="perf-1", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_performer_identity", verdict.reason)

    def test_pubkey_secret_mismatch_raises(self):
        log = PerformerLog()
        with self.assertRaises(AdtechError):
            self._bind(log, authority_pubkey_hex=self.hex("d"))

    def test_chain_break_raises(self):
        log = PerformerLog()
        self._bind(log)
        with self.assertRaises(AdtechError):
            self._bind(log, receipt_id="pr-2", performer_id="perf-2", prev_digest="wrong")


class TestTestimonialGate(_Base):
    def test_ai_persona_efficacy_refused(self):
        verdict = testimonial_existence_gate(
            persona_kind="ai_persona", claims_efficacy=True, evidence_digest=self.hex("e")
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("testimonial_refused", verdict.reason)

    def test_ai_persona_no_efficacy_allowed(self):
        verdict = testimonial_existence_gate(
            persona_kind="ai_persona", claims_efficacy=False, evidence_digest=self.hex("e")
        )
        self.assertTrue(verdict.allowed)

    def test_real_person_allowed(self):
        verdict = testimonial_existence_gate(
            persona_kind="real_person", claims_efficacy=True, evidence_digest=self.hex("e")
        )
        self.assertTrue(verdict.allowed)

    def test_unknown_persona_kind_raises(self):
        with self.assertRaises(AdtechError):
            testimonial_existence_gate(
                persona_kind="ghost_bot", claims_efficacy=True, evidence_digest=self.hex("e")
            )


class TestMaterialityClock(_Base):
    def _assess(self, log, content_id="content-1", materiality="material", **kw):
        args = dict(
            receipt_id="mat-1",
            content_id=content_id,
            materiality=materiality,
            evidence_digest=self.hex("a"),
            assessed_at=_T0,
            expires_at=_T1,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(materiality_assessment_receipt(**args))

    def test_unlabeled_material_denied(self):
        log = MaterialityLog()
        self._assess(log)
        verdict = materiality_label_clock(log=log, content_id="content-1", labeled=False, now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("unlabeled_material", verdict.reason)

    def test_labeled_material_allowed(self):
        log = MaterialityLog()
        self._assess(log)
        verdict = materiality_label_clock(log=log, content_id="content-1", labeled=True, now=_T0)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "authoritative")

    def test_ungraded_content_denied(self):
        log = MaterialityLog()
        verdict = materiality_label_clock(log=log, content_id="unknown", labeled=True, now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("ungraded_materiality", verdict.reason)

    def test_nonmaterial_unlabeled_allowed_non_authoritative(self):
        log = MaterialityLog()
        self._assess(log, content_id="content-2", materiality="non_material")
        verdict = materiality_label_clock(log=log, content_id="content-2", labeled=False, now=_T0)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "non_authoritative")

    def test_bad_materiality_raises(self):
        log = MaterialityLog()
        with self.assertRaises(AdtechError):
            self._assess(log, materiality="sort_of_material")


class TestWatermark(_Base):
    def _mark(self, log, content_digest, **kw):
        args = dict(
            receipt_id="wm-1",
            content_digest=content_digest,
            marking_method="c2pa",
            decode_evidence_digest=self.hex("b"),
            issued_at=_T0,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(machine_readable_marking(**args))

    def test_unmarked_content_denied(self):
        log = WatermarkLog()
        verdict = check_machine_reading(log=log, content_digest=self.hex("a"), now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_watermark", verdict.reason)

    def test_marked_content_allowed(self):
        log = WatermarkLog()
        self._mark(log, self.hex("a"))
        log.verify()
        verdict = check_machine_reading(log=log, content_digest=self.hex("a"), now=_T0)
        self.assertTrue(verdict.allowed)

    def test_unknown_method_raises(self):
        log = WatermarkLog()
        with self.assertRaises(AdtechError):
            self._mark(log, self.hex("a"), marking_method="handshake")


class TestJurisdictionMatrix(_Base):
    def _pin(self, log, deployment_id="dep-1", matrix_digest=None):
        log.append(
            jurisdiction_matrix_pin(
                receipt_id="mx-1",
                deployment_id=deployment_id,
                matrix_digest=matrix_digest or jurisdiction_matrix_digest(),
                pinned_at=_T0,
                authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED,
                prev_digest=self.prev(log),
            )
        )

    def test_matrix_digest_deterministic(self):
        self.assertEqual(jurisdiction_matrix_digest(), jurisdiction_matrix_digest())

    def test_current_pin_allowed(self):
        log = MatrixLog()
        self._pin(log)
        log.verify()
        verdict = check_matrix_pin(log=log, deployment_id="dep-1", now=_T0)
        self.assertTrue(verdict.allowed)

    def test_stale_pin_denied(self):
        log = MatrixLog()
        self._pin(log, matrix_digest=self.hex("f"))
        verdict = check_matrix_pin(log=log, deployment_id="dep-1", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("matrix_mismatch", verdict.reason)

    def test_unpinned_deployment_denied(self):
        log = MatrixLog()
        verdict = check_matrix_pin(log=log, deployment_id="nope", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("matrix_mismatch", verdict.reason)


class TestDarkPatternScreen(_Base):
    def _screen(self, log, interface_id="ui-1", observed=()):
        log.append(
            dark_pattern_screen(
                screen_id="dp-1",
                interface_id=interface_id,
                observed_patterns=observed,
                screened_at=_T0,
                authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED,
                prev_digest=self.prev(log),
            )
        )

    def test_unscreened_interface_denied(self):
        log = DarkPatternLog()
        verdict = check_interface(log=log, interface_id="ui-ghost", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_dark_pattern_screen", verdict.reason)

    def test_clean_screen_allowed(self):
        log = DarkPatternLog()
        self._screen(log)
        log.verify()
        verdict = check_interface(log=log, interface_id="ui-1", now=_T0)
        self.assertTrue(verdict.allowed)

    def test_detected_pattern_denied(self):
        log = DarkPatternLog()
        self._screen(log, interface_id="ui-2", observed=("false_urgency", "roach_motel"))
        verdict = check_interface(log=log, interface_id="ui-2", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("dark_pattern", verdict.reason)
        self.assertIn("false_urgency", verdict.reason)

    def test_unknown_pattern_raises(self):
        log = DarkPatternLog()
        with self.assertRaises(AdtechError):
            self._screen(log, observed=("mind_control",))

    def test_catalog_has_37_patterns(self):
        self.assertEqual(len(DARK_PATTERN_CATALOG), 37)
        self.assertEqual(len(set(DARK_PATTERN_CATALOG)), 37)


class TestBriefBinding(_Base):
    def _bind_brief(self, log, brief_id="brief-1", objectives=("promote_product_x",)):
        log.append(
            agentic_brief_binding(
                brief_id=brief_id,
                declared_objectives=objectives,
                constraints_digest=self.hex("c"),
                issued_at=_T0,
                authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED,
                prev_digest=self.prev(log),
            )
        )

    def test_aligned_objectives_allowed(self):
        log = BriefLog()
        self._bind_brief(log)
        log.verify()
        verdict = check_objective_drift(
            log=log, brief_id="brief-1",
            observed_objectives=("promote_product_x",), now=_T0,
        )
        self.assertTrue(verdict.allowed)

    def test_drifted_objectives_denied(self):
        log = BriefLog()
        self._bind_brief(log)
        verdict = check_objective_drift(
            log=log, brief_id="brief-1",
            observed_objectives=("promote_product_x", "harvest_emails"), now=_T0,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("brief_drift", verdict.reason)

    def test_unbound_brief_denied(self):
        log = BriefLog()
        verdict = check_objective_drift(
            log=log, brief_id="ghost", observed_objectives=("x",), now=_T0,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("unbound_brief", verdict.reason)

    def test_objective_order_insensitive(self):
        log = BriefLog()
        self._bind_brief(log, brief_id="b2", objectives=("a", "b"))
        verdict = check_objective_drift(
            log=log, brief_id="b2", observed_objectives=("b", "a"), now=_T0,
        )
        self.assertTrue(verdict.allowed)


class TestLiabilityPin(_Base):
    def _pin(self, log, platform_id="platform-1", **kw):
        args = dict(
            receipt_id="lp-1",
            platform_id=platform_id,
            regimes=("CN_SAMR", "KR_AI_BASIC"),
            attestation_digest=self.hex("d"),
            pinned_at=_T0,
            expires_at=_T1,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(platform_liability_pin(**args))

    def test_pinned_platform_allowed(self):
        log = LiabilityLog()
        self._pin(log)
        log.verify()
        verdict = check_platform_liability(log=log, platform_id="platform-1", now=_T0)
        self.assertTrue(verdict.allowed)

    def test_unpinned_platform_denied(self):
        log = LiabilityLog()
        verdict = check_platform_liability(log=log, platform_id="ghost", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_liability_pin", verdict.reason)

    def test_expired_pin_denied(self):
        log = LiabilityLog()
        self._pin(log, pinned_at=_T0 - 100, expires_at=_T0 - 1)
        verdict = check_platform_liability(log=log, platform_id="platform-1", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_liability_pin", verdict.reason)

    def test_unknown_regime_raises(self):
        log = LiabilityLog()
        with self.assertRaises(AdtechError):
            self._pin(log, regimes=("MARS_REGIME",))


class TestFatigueGuard(_Base):
    def _sample(self, log, monitor_id="mon-1", **kw):
        args = dict(
            monitor_id=monitor_id,
            content_id="content-9",
            exposures=500,
            distinct_formats=2,
            comprehension_bps=8000,
            window_days=7,
            measured_at=_T0,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(label_fatigue_sample(**args))

    def test_healthy_labels_allowed(self):
        log = FatigueLog()
        self._sample(log)
        log.verify()
        verdict = label_fatigue_guard(log=log, monitor_id="mon-1", now=_T0)
        self.assertTrue(verdict.allowed)

    def test_unmonitored_denied(self):
        log = FatigueLog()
        verdict = label_fatigue_guard(log=log, monitor_id="ghost", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("no_fatigue_monitor", verdict.reason)

    def test_low_comprehension_triggers_review(self):
        log = FatigueLog()
        self._sample(log, comprehension_bps=MIN_COMPREHENSION_BPS - 1)
        verdict = label_fatigue_guard(log=log, monitor_id="mon-1", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("fatigue_review", verdict.reason)

    def test_exposure_overflow_triggers_review(self):
        log = FatigueLog()
        self._sample(
            log,
            exposures=(MAX_EXPOSURES_PER_FORMAT + 1) * 3,
            distinct_formats=3,
        )
        verdict = label_fatigue_guard(log=log, monitor_id="mon-1", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("fatigue_review", verdict.reason)


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        verdict = testimonial_existence_gate(
            persona_kind="real_person", claims_efficacy=False, evidence_digest="e" * 64
        )
        event = adtech_agents.adtech_audit_event(verdict, action="testimonial.screen")
        self.assertEqual(event["action"], "testimonial.screen")
        self.assertTrue(event["verdict_allowed"])
        self.assertEqual(event["schema_version"], adtech_agents.ADTECH_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
