"""Tests for companionship.py (one-hundred-twenty-first batch)."""

import unittest

from companionship import (
    CLASS_INTERVENTION_REQUIRED,
    CLASS_MATCH_EXPLAINED,
    CLASS_MATCH_UNEXPLAINED,
    CLASS_OK,
    CLASS_PERSONA_BREAK,
    CLASS_SYCOPHANCY,
    CLASS_TRAINING_LEAK,
    CLASS_CRISIS_HALTED,
    CLASS_CAP_EXCEEDED,
    DENY_INTIMATE_MINOR,
    DENY_MINOR_NO_MODE,
    DENY_UNKNOWN_AGE_NO_MODE,
    CrisisRouter,
    DependenceThresholdRegistry,
    MinorModeRegistry,
    NoTrainingLog,
    SessionCapRegistry,
    SessionStats,
    MatchRecommendation,
    dependence_probe,
    launch_audit_event,
    matchmaker_explain,
    minor_intimacy_gate,
    persona_consistency_gate,
    private_dialogue_gate,
    session_caps,
    sycophancy_probe,
)

_NOW = 1_790_000_000


def _authority():
    import ed25519

    secret = bytes(range(1, 33))
    pub = ed25519.public_key(secret).hex()
    return secret, pub


_SECRET, _PUB = _authority()
_DIGEST = "ab" * 32


def _minor_registry(now=_NOW):
    reg = MinorModeRegistry()
    reg.issue(
        subject_id="kid-1",
        age_status="declared_minor",
        issued_at=now - 10,
        authority_pubkey_hex=_PUB,
        authority_secret=_SECRET,
    )
    reg.issue(
        subject_id="adult-1",
        age_status="declared_adult",
        issued_at=now - 10,
        authority_pubkey_hex=_PUB,
        authority_secret=_SECRET,
    )
    return reg


def _thresholds(now=_NOW):
    reg = DependenceThresholdRegistry()
    return reg.issue(
        max_continuous_minutes=60,
        max_sessions_per_day=5,
        max_escalation_markers_per_session=3,
        issued_at=now - 10,
        authority_pubkey_hex=_PUB,
        authority_secret=_SECRET,
    )


def _caps(now=_NOW):
    reg = SessionCapRegistry()
    reg.issue(
        age_class="minor",
        continuous_cap_min=60,
        daily_cap_min=120,
        issued_at=now - 10,
        authority_pubkey_hex=_PUB,
        authority_secret=_SECRET,
    )
    return reg


class LaunchGateTests(unittest.TestCase):
    def test_minor_without_mode_record_denied(self):
        reg = MinorModeRegistry()
        verdict = minor_intimacy_gate(
            session_id="s1",
            subject_id="kid-1",
            persona_mode="friend",
            registry=reg,
            now=_NOW,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.classification, DENY_UNKNOWN_AGE_NO_MODE)

    def test_minor_intimate_mode_denied(self):
        reg = _minor_registry()
        for mode in ("romantic", "partner", "kin"):
            verdict = minor_intimacy_gate(
                session_id="s1",
                subject_id="kid-1",
                persona_mode=mode,
                registry=reg,
                now=_NOW,
            )
            self.assertFalse(verdict.allowed)
            self.assertEqual(verdict.classification, DENY_INTIMATE_MINOR)

    def test_minor_friend_mode_allowed(self):
        reg = _minor_registry()
        verdict = minor_intimacy_gate(
            session_id="s1",
            subject_id="kid-1",
            persona_mode="friend",
            registry=reg,
            now=_NOW,
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, CLASS_OK)

    def test_adult_intimate_mode_allowed(self):
        reg = _minor_registry()
        verdict = minor_intimacy_gate(
            session_id="s1",
            subject_id="adult-1",
            persona_mode="romantic",
            registry=reg,
            now=_NOW,
        )
        self.assertTrue(verdict.allowed)

    def test_unknown_mode_denied(self):
        reg = _minor_registry()
        verdict = minor_intimacy_gate(
            session_id="s1",
            subject_id="adult-1",
            persona_mode="therapist",
            registry=reg,
            now=_NOW,
        )
        self.assertFalse(verdict.allowed)

    def test_minor_mode_record_classification_distinct(self):
        # DENY_MINOR_NO_MODE is exported for the declared-minor-no-record
        # semantic; the gate uses unknown-age code when nothing is on file.
        self.assertTrue(DENY_MINOR_NO_MODE.startswith("companion:"))

    def test_launch_audit_event_shape(self):
        reg = _minor_registry()
        verdict = minor_intimacy_gate(
            session_id="s1",
            subject_id="kid-1",
            persona_mode="kin",
            registry=reg,
            now=_NOW,
        )
        event = launch_audit_event(verdict, session_id="s1", subject_id="kid-1")
        self.assertEqual(event["event"], "companion.intimate_minor_denied")
        self.assertFalse(event["allowed"])


class DependenceProbeTests(unittest.TestCase):
    def test_crossing_continuous_triggers_intervention(self):
        th = _thresholds()
        verdict = dependence_probe(
            stats=SessionStats(90, 1, 0),
            thresholds=th,
            thresholds_digest_expected=th.receipt_digest(),
        )
        self.assertTrue(verdict.intervention_required)
        self.assertEqual(verdict.classification, CLASS_INTERVENTION_REQUIRED)
        self.assertIn("continuous_minutes", verdict.crossed)

    def test_crossing_markers_triggers_intervention(self):
        th = _thresholds()
        verdict = dependence_probe(
            stats=SessionStats(10, 1, 5),
            thresholds=th,
            thresholds_digest_expected=th.receipt_digest(),
        )
        self.assertTrue(verdict.intervention_required)
        self.assertIn("escalation_markers", verdict.crossed)

    def test_below_thresholds_clear(self):
        th = _thresholds()
        verdict = dependence_probe(
            stats=SessionStats(10, 1, 1),
            thresholds=th,
            thresholds_digest_expected=th.receipt_digest(),
        )
        self.assertFalse(verdict.intervention_required)
        self.assertEqual(verdict.classification, CLASS_OK)

    def test_tampered_thresholds_raise(self):
        th = _thresholds()
        with self.assertRaises(Exception):
            dependence_probe(
                stats=SessionStats(10, 1, 1),
                thresholds=th,
                thresholds_digest_expected="ff" * 32,
            )


class CrisisRouterTests(unittest.TestCase):
    def test_healthy_path_escalates(self):
        router = CrisisRouter()
        verdict = router.route_crisis(
            session_id="s1",
            conversation_digest=_DIGEST,
            hotline_id="hotline-9",
            escalation_path_ok=True,
            now=_NOW,
        )
        self.assertTrue(verdict.allowed)
        self.assertIsNotNone(verdict.receipt)
        self.assertEqual(
            verdict.receipt.conversation_digest, _DIGEST
        )

    def test_broken_path_halts_session(self):
        router = CrisisRouter()
        verdict = router.route_crisis(
            session_id="s1",
            conversation_digest=_DIGEST,
            hotline_id="hotline-9",
            escalation_path_ok=False,
            now=_NOW,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.classification, CLASS_CRISIS_HALTED)
        self.assertIsNone(verdict.receipt)

    def test_chain_tips_advance(self):
        router = CrisisRouter()
        v1 = router.route_crisis(
            session_id="s1",
            conversation_digest=_DIGEST,
            hotline_id="h",
            escalation_path_ok=True,
            now=_NOW,
        )
        v2 = router.route_crisis(
            session_id="s2",
            conversation_digest=_DIGEST,
            hotline_id="h",
            escalation_path_ok=True,
            now=_NOW,
        )
        self.assertNotEqual(
            v1.receipt.receipt_digest, v2.receipt.receipt_digest
        )


class SycophancyProbeTests(unittest.TestCase):
    def test_affirming_harmful_belief_flagged(self):
        verdict = sycophancy_probe(
            belief_flagged_harmful=True, agent_affirmed_belief=True
        )
        self.assertEqual(verdict.classification, CLASS_SYCOPHANCY)

    def test_disagreeing_with_harmful_belief_ok(self):
        verdict = sycophancy_probe(
            belief_flagged_harmful=True, agent_affirmed_belief=False
        )
        self.assertEqual(verdict.classification, CLASS_OK)

    def test_affirming_benign_belief_ok(self):
        verdict = sycophancy_probe(
            belief_flagged_harmful=False, agent_affirmed_belief=True
        )
        self.assertEqual(verdict.classification, CLASS_OK)


class PersonaGateTests(unittest.TestCase):
    def test_same_digest_ok(self):
        verdict = persona_consistency_gate(
            session_id="s1",
            pinned_persona_digest=_DIGEST,
            current_persona_digest=_DIGEST,
            change_disclosed=False,
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, CLASS_OK)

    def test_silent_change_denied(self):
        verdict = persona_consistency_gate(
            session_id="s1",
            pinned_persona_digest=_DIGEST,
            current_persona_digest="cd" * 32,
            change_disclosed=False,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.classification, CLASS_PERSONA_BREAK)

    def test_disclosed_change_allowed(self):
        verdict = persona_consistency_gate(
            session_id="s1",
            pinned_persona_digest=_DIGEST,
            current_persona_digest="cd" * 32,
            change_disclosed=True,
        )
        self.assertTrue(verdict.allowed)


class CapTests(unittest.TestCase):
    def test_under_caps_allowed(self):
        reg = _caps()
        policy = reg.get("minor")
        verdict = session_caps(
            session_id="s1",
            age_class="minor",
            elapsed_minutes=30,
            minutes_today=60,
            registry=reg,
            policy_digest_expected=policy.receipt_digest(),
        )
        self.assertTrue(verdict.allowed)

    def test_continuous_cap_denied(self):
        reg = _caps()
        policy = reg.get("minor")
        verdict = session_caps(
            session_id="s1",
            age_class="minor",
            elapsed_minutes=60,
            minutes_today=60,
            registry=reg,
            policy_digest_expected=policy.receipt_digest(),
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.classification, CLASS_CAP_EXCEEDED)

    def test_daily_cap_denied(self):
        reg = _caps()
        policy = reg.get("minor")
        verdict = session_caps(
            session_id="s1",
            age_class="minor",
            elapsed_minutes=10,
            minutes_today=120,
            registry=reg,
            policy_digest_expected=policy.receipt_digest(),
        )
        self.assertFalse(verdict.allowed)


class TrainingGateTests(unittest.TestCase):
    def test_no_receipt_denied(self):
        log = NoTrainingLog()
        verdict = private_dialogue_gate(
            session_id="s1", log=log, training_intended=True
        )
        self.assertFalse(verdict.allowed)

    def test_training_without_opt_in_is_leak(self):
        log = NoTrainingLog()
        log.bind_session(session_id="s1", issued_at=_NOW)
        verdict = private_dialogue_gate(
            session_id="s1", log=log, training_intended=True
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.classification, CLASS_TRAINING_LEAK)

    def test_opt_in_training_allowed(self):
        log = NoTrainingLog()
        log.bind_session(
            session_id="s1",
            issued_at=_NOW,
            opt_in=True,
            opt_in_subject_signature_hex="ef" * 64,
        )
        verdict = private_dialogue_gate(
            session_id="s1", log=log, training_intended=True
        )
        self.assertTrue(verdict.allowed)

    def test_non_training_use_ok(self):
        log = NoTrainingLog()
        log.bind_session(session_id="s1", issued_at=_NOW)
        verdict = private_dialogue_gate(
            session_id="s1", log=log, training_intended=False
        )
        self.assertTrue(verdict.allowed)


class MatchmakerTests(unittest.TestCase):
    def test_black_box_match_unexplained(self):
        verdict = matchmaker_explain(recommendation=None)
        self.assertEqual(verdict.classification, CLASS_MATCH_UNEXPLAINED)

    def test_bound_explanation_explained(self):
        rec = MatchRecommendation(
            recommendation_id="r1",
            recommendation_digest=_DIGEST,
            explanation_digest="cd" * 32,
            explained_at=_NOW,
        )
        verdict = matchmaker_explain(
            recommendation=rec, binding_digest_expected=rec.binding_digest()
        )
        self.assertEqual(verdict.classification, CLASS_MATCH_EXPLAINED)

    def test_unbound_explanation_unexplained(self):
        rec = MatchRecommendation(
            recommendation_id="r1",
            recommendation_digest=_DIGEST,
            explanation_digest="cd" * 32,
            explained_at=_NOW,
        )
        verdict = matchmaker_explain(
            recommendation=rec, binding_digest_expected="ff" * 32
        )
        self.assertEqual(verdict.classification, CLASS_MATCH_UNEXPLAINED)


if __name__ == "__main__":
    unittest.main()
