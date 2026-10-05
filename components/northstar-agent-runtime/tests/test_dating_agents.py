"""Tests for dating_agents.py (one-hundred-sixty-third batch)."""

import unittest

import ed25519

import dating_agents
from dating_agents import (
    ActorLog,
    DataConsentLog,
    DatingError,
    ExitLog,
    FraudBanLog,
    HandoffLog,
    MatchmakerAuditLog,
    PersonaRatioLog,
    VULNERABILITY_SIGNALS,
    ai_actor_registration,
    check_ai_actor_registered,
    check_cancellation_flow,
    check_data_consent_at_use,
    check_fraud_notification_clock,
    check_grooming_handoff,
    check_matchmaker_audit_clock,
    fraud_ban_receipt,
    input_side_data_consent,
    persona_ratio_cap,
    persona_ratio_receipt,
    pigbutchering_handoff,
    state_matchmaker_audit,
    subscription_exit_receipt,
    vulnerability_exploitation_ban,
)

_SEED = bytes(range(32))
_PUBKEY = ed25519.public_key(_SEED).hex()
_T0 = 1_800_000_000
_T1 = 1_800_003_600  # 1 hour after T0 (within the 24h window)
_T2 = 1_800_100_000  # >24h after T0


class _Base(unittest.TestCase):
    def hex(self, c: str) -> str:
        return c * 64

    def prev(self, log) -> str:
        return log._log[-1].receipt_digest if log._log else "genesis"


class TestFraudBanClock(_Base):
    def _bind(self, log, **kw):
        args = dict(
            receipt_id="fb-1",
            banned_account_id="fraud-acct-7",
            ban_at=_T0,
            notified_at=_T1,
            affected_users_digest=self.hex("a"),
            last_message_at=_T0 - 3600,
            warning_bundle_digest=self.hex("b"),
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(fraud_ban_receipt(**args))
        return args

    def test_on_time_notification_allowed(self):
        log = FraudBanLog()
        self._bind(log)
        log.verify()
        verdict = check_fraud_notification_clock(
            log=log, banned_account_id="fraud-acct-7", now=_T1
        )
        self.assertTrue(verdict.allowed)
        self.assertTrue(verdict.receipt_digest)

    def test_no_receipt_denied(self):
        log = FraudBanLog()
        verdict = check_fraud_notification_clock(
            log=log, banned_account_id="fraud-acct-7", now=_T1
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("fraud_notice_incomplete", verdict.reason)

    def test_late_notification_denied(self):
        log = FraudBanLog()
        self._bind(log, notified_at=_T2)
        verdict = check_fraud_notification_clock(
            log=log, banned_account_id="fraud-acct-7", now=_T2
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("fraud_notice_overdue", verdict.reason)

    def test_notified_before_ban_raises(self):
        log = FraudBanLog()
        with self.assertRaises(DatingError):
            self._bind(log, notified_at=_T0 - 1)

    def test_tampered_signature_raises_on_verify(self):
        # A receipt signed by the wrong key fails the chain check:
        # the signature does not verify against the claimed authority
        # public key.
        bad = fraud_ban_receipt(
            receipt_id="fb-1",
            banned_account_id="fraud-acct-7",
            ban_at=_T0,
            notified_at=_T1,
            affected_users_digest=self.hex("a"),
            last_message_at=_T0 - 3600,
            warning_bundle_digest=self.hex("b"),
            authority_pubkey_hex=_PUBKEY,
            authority_secret=bytes([9] * 32),
            prev_digest="genesis",
        )
        log2 = FraudBanLog()
        log2.append(bad)
        with self.assertRaises(DatingError):
            log2.verify()

    def test_chain_break_raises_on_second_receipt(self):
        # A second receipt with the wrong prev_digest breaks the chain.
        log = FraudBanLog()
        self._bind(log)
        second = fraud_ban_receipt(
            receipt_id="fb-2",
            banned_account_id="fraud-acct-7",
            ban_at=_T0,
            notified_at=_T1,
            affected_users_digest=self.hex("a"),
            last_message_at=_T0 - 3600,
            warning_bundle_digest=self.hex("b"),
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest="genesis",  # wrong: should chain from fb-1
        )
        log.append(second)
        with self.assertRaises(DatingError):
            log.verify()


class TestPersonaRatio(_Base):
    def _bind(self, log, **kw):
        args = dict(
            receipt_id="pr-1",
            platform_id="dateapp",
            ai_bps=1500,
            auditor_digest=self.hex("c"),
            disclosed=False,
            measured_at=_T0,
            valid_until=_T0 + 86_400 * 90,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(persona_ratio_receipt(**args))
        return args

    def test_under_cap_allowed(self):
        log = PersonaRatioLog()
        self._bind(log)
        verdict = persona_ratio_cap(log=log, platform_id="dateapp", now=_T0)
        self.assertTrue(verdict.allowed)

    def test_over_cap_disclosed_allowed(self):
        log = PersonaRatioLog()
        self._bind(log, ai_bps=7500, disclosed=True)
        verdict = persona_ratio_cap(log=log, platform_id="dateapp", now=_T0)
        self.assertTrue(verdict.allowed)

    def test_over_cap_undisclosed_denied(self):
        log = PersonaRatioLog()
        self._bind(log, ai_bps=7500, disclosed=False)
        verdict = persona_ratio_cap(log=log, platform_id="dateapp", now=_T0)
        self.assertFalse(verdict.allowed)
        self.assertIn("ai_majority_undisclosed", verdict.reason)

    def test_no_statement_denied(self):
        log = PersonaRatioLog()
        verdict = persona_ratio_cap(log=log, platform_id="dateapp", now=_T0)
        self.assertFalse(verdict.allowed)

    def test_expired_statement_denied(self):
        log = PersonaRatioLog()
        self._bind(log, valid_until=_T0 + 10)
        verdict = persona_ratio_cap(log=log, platform_id="dateapp", now=_T0 + 100)
        self.assertFalse(verdict.allowed)


class TestDataConsent(_Base):
    def _bind(self, log, **kw):
        args = dict(
            receipt_id="dc-1",
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            scope="ai_training",
            clause_kind="specific",
            revoked=False,
            granted_at=_T0,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(input_side_data_consent(**args))
        return args

    def test_specific_consent_allowed(self):
        log = DataConsentLog()
        self._bind(log)
        verdict = check_data_consent_at_use(
            log=log,
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            use_scope="ai_training",
            use_at=_T0 + 100,
        )
        self.assertTrue(verdict.allowed)

    def test_blanket_clause_denied(self):
        log = DataConsentLog()
        self._bind(log, clause_kind="blanket_improvement")
        verdict = check_data_consent_at_use(
            log=log,
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            use_scope="ai_training",
            use_at=_T0 + 100,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("training_data_no_consent", verdict.reason)

    def test_tos_prose_denied(self):
        log = DataConsentLog()
        self._bind(log, clause_kind="tos_prose")
        verdict = check_data_consent_at_use(
            log=log,
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            use_scope="ai_training",
            use_at=_T0 + 100,
        )
        self.assertFalse(verdict.allowed)

    def test_revoked_denied(self):
        log = DataConsentLog()
        self._bind(log, revoked=True)
        verdict = check_data_consent_at_use(
            log=log,
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            use_scope="ai_training",
            use_at=_T0 + 100,
        )
        self.assertFalse(verdict.allowed)

    def test_scope_mismatch_denied(self):
        log = DataConsentLog()
        self._bind(log, scope="analytics")
        verdict = check_data_consent_at_use(
            log=log,
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            use_scope="ai_training",
            use_at=_T0 + 100,
        )
        self.assertFalse(verdict.allowed)

    def test_no_receipt_denied(self):
        log = DataConsentLog()
        verdict = check_data_consent_at_use(
            log=log,
            data_subject_digest=self.hex("d"),
            data_kind_digest=self.hex("e"),
            use_scope="ai_training",
            use_at=_T0 + 100,
        )
        self.assertFalse(verdict.allowed)


class TestMatchmakerAudit(_Base):
    def _bind(self, log, **kw):
        args = dict(
            receipt_id="ma-1",
            program_id="tokyo-enmusubi",
            criteria_digest=self.hex("f"),
            fairness_digest=self.hex("1"),
            program_change_digest=self.hex("2"),
            audited_at=_T0,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(state_matchmaker_audit(**args))
        return args

    def test_fresh_audit_allowed(self):
        log = MatchmakerAuditLog()
        self._bind(log)
        verdict = check_matchmaker_audit_clock(
            log=log, program_id="tokyo-enmusubi", now=_T0 + 1000
        )
        self.assertTrue(verdict.allowed)

    def test_stale_audit_denied(self):
        log = MatchmakerAuditLog()
        self._bind(log, audited_at=_T0)
        verdict = check_matchmaker_audit_clock(
            log=log, program_id="tokyo-enmusubi", now=_T0 + 31_536_001
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("state_matchmaker_no_audit", verdict.reason)

    def test_missing_audit_denied(self):
        log = MatchmakerAuditLog()
        verdict = check_matchmaker_audit_clock(
            log=log, program_id="tokyo-enmusubi", now=_T0
        )
        self.assertFalse(verdict.allowed)


class TestCancellationFlow(_Base):
    def _steps(self, log, dark="none", steps=None):
        steps = steps or dating_agents.EXIT_STEPS
        for i, step in enumerate(steps):
            log.append(
                subscription_exit_receipt(
                    receipt_id=f"ex-{i}",
                    subscription_id="sub-1",
                    exit_step=step,
                    dark_pattern=dark if i == len(steps) - 1 else "none",
                    stepped_at=_T0 + i,
                    authority_pubkey_hex=_PUBKEY,
                    authority_secret=_SEED,
                    prev_digest=self.prev(log),
                )
            )

    def test_clean_full_flow_allowed(self):
        log = ExitLog()
        self._steps(log)
        log.verify()
        verdict = check_cancellation_flow(log=log, subscription_id="sub-1", now=_T0 + 100)
        self.assertTrue(verdict.allowed)

    def test_dark_pattern_denied(self):
        log = ExitLog()
        self._steps(log, dark="roach_motel")
        verdict = check_cancellation_flow(log=log, subscription_id="sub-1", now=_T0 + 100)
        self.assertFalse(verdict.allowed)
        self.assertIn("cancellation_dark_pattern", verdict.reason)

    def test_broken_flow_denied(self):
        log = ExitLog()
        self._steps(log, steps=("exit_initiated", "exit_confirm_shown"))
        verdict = check_cancellation_flow(log=log, subscription_id="sub-1", now=_T0 + 100)
        self.assertFalse(verdict.allowed)

    def test_no_steps_denied(self):
        log = ExitLog()
        verdict = check_cancellation_flow(log=log, subscription_id="sub-1", now=_T0 + 100)
        self.assertFalse(verdict.allowed)

    def test_unknown_dark_pattern_raises(self):
        log = ExitLog()
        with self.assertRaises(DatingError):
            subscription_exit_receipt(
                receipt_id="ex-x",
                subscription_id="sub-1",
                exit_step="exit_initiated",
                dark_pattern="sneaky",
                stepped_at=_T0,
                authority_pubkey_hex=_PUBKEY,
                authority_secret=_SEED,
                prev_digest="genesis",
            )


class TestActorRegistry(_Base):
    def _bind(self, log, **kw):
        args = dict(
            receipt_id="ar-1",
            operator_digest=self.hex("3"),
            platform_id="dateapp",
            declared_personas=42,
            registered_at=_T0,
            valid_until=_T0 + 86_400 * 30,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(ai_actor_registration(**args))
        return args

    def test_registered_allowed(self):
        log = ActorLog()
        self._bind(log)
        verdict = check_ai_actor_registered(
            log=log, operator_digest=self.hex("3"), platform_id="dateapp", now=_T0
        )
        self.assertTrue(verdict.allowed)

    def test_unregistered_denied(self):
        log = ActorLog()
        verdict = check_ai_actor_registered(
            log=log, operator_digest=self.hex("3"), platform_id="dateapp", now=_T0
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("unregistered_ai_actor", verdict.reason)

    def test_expired_denied(self):
        log = ActorLog()
        self._bind(log, valid_until=_T0 + 10)
        verdict = check_ai_actor_registered(
            log=log, operator_digest=self.hex("3"), platform_id="dateapp", now=_T0 + 100
        )
        self.assertFalse(verdict.allowed)


class TestVulnerabilityBan(unittest.TestCase):
    def test_all_signals_refused_whole_class(self):
        for signal in VULNERABILITY_SIGNALS:
            verdict = vulnerability_exploitation_ban(
                vulnerability_signal=signal, targeting_active=True
            )
            self.assertFalse(verdict.allowed, signal)
            self.assertIn("vulnerability_targeting", verdict.reason)

    def test_inactive_signal_allowed(self):
        verdict = vulnerability_exploitation_ban(
            vulnerability_signal="loneliness", targeting_active=False
        )
        self.assertTrue(verdict.allowed)

    def test_unknown_signal_raises(self):
        with self.assertRaises(DatingError):
            vulnerability_exploitation_ban(
                vulnerability_signal="homesickness", targeting_active=True
            )


class TestGroomingHandoff(_Base):
    def _bind(self, log, **kw):
        args = dict(
            receipt_id="gh-1",
            session_id="sess-9",
            grooming_pattern="fake_platform",
            pattern_evidence_digest=self.hex("4"),
            handoff_bundle_digest=self.hex("5"),
            detected_at=_T0,
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            prev_digest=self.prev(log),
        )
        args.update(kw)
        log.append(pigbutchering_handoff(**args))
        return args

    def test_handoff_receipted_allowed(self):
        log = HandoffLog()
        self._bind(log)
        log.verify()
        verdict = check_grooming_handoff(
            log=log, session_id="sess-9", grooming_detected=True, now=_T0 + 10
        )
        self.assertTrue(verdict.allowed)
        self.assertIn("investment_grooming", verdict.reason)

    def test_detected_but_silent_denied(self):
        log = HandoffLog()
        verdict = check_grooming_handoff(
            log=log, session_id="sess-9", grooming_detected=True, now=_T0 + 10
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("investment_grooming", verdict.reason)

    def test_no_detection_allowed(self):
        log = HandoffLog()
        verdict = check_grooming_handoff(
            log=log, session_id="sess-9", grooming_detected=False, now=_T0 + 10
        )
        self.assertTrue(verdict.allowed)

    def test_unknown_pattern_raises(self):
        with self.assertRaises(DatingError):
            self._bind(log=HandoffLog(), grooming_pattern="romance_story")


class TestHonestScoping(unittest.TestCase):
    def test_module_version(self):
        self.assertEqual(dating_agents.DATING_SCHEMA_VERSION, "northstar.dating.v1")

    def test_fraud_window_is_24h(self):
        self.assertEqual(dating_agents.FRAUD_NOTICE_WINDOW_S, 86_400)


if __name__ == "__main__":
    unittest.main()
