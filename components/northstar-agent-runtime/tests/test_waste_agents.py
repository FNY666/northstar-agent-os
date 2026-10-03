"""Tests for waste_agents.py (one-hundred-thirty-ninth batch)."""

import unittest

import ed25519

import waste_agents
from waste_agents import (
    PurityLog,
    PicLog,
    BatteryPassportLog,
    ClaimEvidenceLog,
    TransitionLog,
    HardwareLifecycleLog,
    DumpingAlertLog,
    FireTriageLog,
    WasteError,
    sorting_purity_receipt,
    basel_pic_binding,
    battery_passport_pin,
    claim_evidence_chain,
    informal_sector_transition,
    ai_hardware_lifecycle,
    dumping_alert_binding,
    battery_fire_triage,
    check_purity_claim,
    check_movement,
    check_battery_decommission,
    check_claim_evidence,
    check_transition_plan,
    check_hardware_lifecycle,
    check_dumping_alert,
    check_fire_triage,
)

_SEED = bytes(range(32))
_PUBKEY = ed25519.public_key(_SEED).hex()
_T0 = 1_800_000_000
_T1 = 1_800_003_600


class _Base(unittest.TestCase):
    def hex(self, c: str) -> str:
        return (c * 64)


class TestPurityReceipt(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="pur-1",
            claim_id="cl-1",
            test_protocol_digest=self.hex("a"),
            batch_id="batch-7",
            batch_size=100,
            measured_sample_n=10,
            measured_purity_bps=9960,
            issued_by="lab",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return sorting_purity_receipt(**args)

    def test_allow_bound_claim(self):
        log = PurityLog()
        r = self._receipt()
        log.append(r)
        v = check_purity_claim(
            log=log, batch_id="batch-7", claimed_purity_bps=9960, now=_T0
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_cherry_pick_single_sample(self):
        log = PurityLog()
        log.append(self._receipt(measured_sample_n=1))
        v = check_purity_claim(
            log=log, batch_id="batch-7", claimed_purity_bps=9960, now=_T0
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.cherry_picked"))

    def test_no_receipt_ungraded(self):
        v = check_purity_claim(
            log=PurityLog(), batch_id="batch-7", claimed_purity_bps=9960, now=_T0
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.ungraded_purity"))

    def test_overclaim_above_measured_plus_tolerance(self):
        log = PurityLog()
        log.append(self._receipt(measured_purity_bps=9900))
        v = check_purity_claim(
            log=log, batch_id="batch-7", claimed_purity_bps=9970, now=_T0
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.ungraded_purity"))

    def test_sample_exceeding_batch_is_malformed(self):
        with self.assertRaises(WasteError):
            self._receipt(measured_sample_n=101)

    def test_expired_receipt(self):
        log = PurityLog()
        log.append(self._receipt())
        v = check_purity_claim(
            log=log, batch_id="batch-7", claimed_purity_bps=9960, now=_T1 + 1
        )
        self.assertFalse(v.allowed)

    def test_tampered_signature_fails_chain_verify(self):
        log = PurityLog()
        r = self._receipt()
        bad = waste_agents.PurityReceipt(**{**r.__dict__, "signature_hex": "ff" * 128})
        log.append(bad)
        with self.assertRaises(WasteError):
            log.verify()


class TestBaselPic(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="pic-1",
            movement_id="mv-1",
            waste_code="A1181",
            origin="US",
            destination="KR",
            pic_receipt_digest=self.hex("b"),
            issued_by="customs",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return basel_pic_binding(**args)

    def test_allow_bound_movement(self):
        log = PicLog()
        log.append(self._receipt())
        v = check_movement(log=log, movement_id="mv-1", now=_T0)
        self.assertTrue(v.allowed)

    def test_no_pic_denied(self):
        v = check_movement(log=PicLog(), movement_id="mv-1", now=_T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_pic"))

    def test_banned_destination_rejected_at_issuance(self):
        with self.assertRaises(WasteError):
            self._receipt(destination="MY")

    def test_unknown_waste_code_rejected(self):
        with self.assertRaises(WasteError):
            self._receipt(waste_code="ZZZ")


class TestBatteryPassport(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="bp-1",
            battery_id="bat-1",
            battery_capacity_wh=5000,
            passport_digest=self.hex("c"),
            recovery_plan_digest=self.hex("d"),
            issued_by="decomm",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return battery_passport_pin(**args)

    def test_allow_pinned(self):
        log = BatteryPassportLog()
        log.append(self._receipt())
        v = check_battery_decommission(
            log=log, battery_id="bat-1", battery_capacity_wh=5000, now=_T0
        )
        self.assertTrue(v.allowed)

    def test_big_battery_without_pin_denied(self):
        v = check_battery_decommission(
            log=BatteryPassportLog(),
            battery_id="bat-9",
            battery_capacity_wh=5000,
            now=_T0,
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_battery_passport"))

    def test_small_battery_exempt(self):
        v = check_battery_decommission(
            log=BatteryPassportLog(),
            battery_id="bat-2",
            battery_capacity_wh=500,
            now=_T0,
        )
        self.assertTrue(v.allowed)


class TestClaimEvidence(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="ce-1",
            claim_id="claim-1",
            claim_text="90% recycled content",
            evidence_tiers=("third_party_cert",),
            evidence_digest=self.hex("e"),
            offset_based=False,
            issued_by="audit",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return claim_evidence_chain(**args)

    def test_allow_authoritative_tier(self):
        log = ClaimEvidenceLog()
        log.append(self._receipt())
        v = check_claim_evidence(log=log, claim_id="claim-1", now=_T0)
        self.assertTrue(v.allowed)

    def test_offset_claim_unlawful_at_issuance(self):
        with self.assertRaises(WasteError):
            self._receipt(offset_based=True)

    def test_no_evidence_denied(self):
        v = check_claim_evidence(log=ClaimEvidenceLog(), claim_id="x", now=_T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_evidence"))

    def test_self_declared_only_denied(self):
        log = ClaimEvidenceLog()
        log.append(self._receipt(evidence_tiers=("self_declared",)))
        v = check_claim_evidence(log=log, claim_id="claim-1", now=_T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_evidence"))


class TestTransition(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="tr-1",
            facility_id="mrf-1",
            pickers_displaced=20,
            transition_plan_digest=self.hex("f"),
            plan_summary="retrain + hire",
            issued_by="ops",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return informal_sector_transition(**args)

    def test_allow_with_plan(self):
        log = TransitionLog()
        log.append(self._receipt())
        v = check_transition_plan(
            log=log, facility_id="mrf-1", pickers_displaced=20, now=_T0
        )
        self.assertTrue(v.allowed)

    def test_no_plan_denied(self):
        v = check_transition_plan(
            log=TransitionLog(), facility_id="mrf-1", pickers_displaced=20, now=_T0
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_transition_plan"))

    def test_zero_displaced_allowed(self):
        v = check_transition_plan(
            log=TransitionLog(), facility_id="mrf-1", pickers_displaced=0, now=_T0
        )
        self.assertTrue(v.allowed)

    def test_plan_undercovers_denied(self):
        log = TransitionLog()
        log.append(self._receipt(pickers_displaced=5))
        v = check_transition_plan(
            log=log, facility_id="mrf-1", pickers_displaced=20, now=_T0
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_transition_plan"))


class TestHardwareLifecycle(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="hw-1",
            workload_id="wl-1",
            hardware_units=64,
            disposal_plan_digest=self.hex("a"),
            env_ledger_receipt_digest=self.hex("b"),
            issued_by="infra",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return ai_hardware_lifecycle(**args)

    def test_allow_bound(self):
        log = HardwareLifecycleLog()
        log.append(self._receipt())
        v = check_hardware_lifecycle(log=log, workload_id="wl-1", now=_T0)
        self.assertTrue(v.allowed)

    def test_undeclared_denied(self):
        v = check_hardware_lifecycle(log=HardwareLifecycleLog(), workload_id="wl-9", now=_T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.unrouted_hardware"))


class TestDumpingAlert(_Base):
    def _alert(self, **kw):
        args = dict(
            receipt_id="da-1",
            alert_id="alert-1",
            channel="aerial_ai",
            image_digest=self.hex("c"),
            location_id="st-5",
            human_verification_digest="",
            issued_by="city",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return dumping_alert_binding(**args)

    def test_unverified_alert_is_lead_only(self):
        log = DumpingAlertLog()
        log.append(self._alert())
        v = check_dumping_alert(log=log, alert_id="alert-1", now=_T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.unverified_alert"))
        self.assertEqual(v.classification, "non_authoritative")

    def test_verified_alert_allowed(self):
        log = DumpingAlertLog()
        log.append(self._alert(human_verification_digest=self.hex("d")))
        v = check_dumping_alert(log=log, alert_id="alert-1", now=_T0)
        self.assertTrue(v.allowed)

    def test_bad_channel_rejected(self):
        with self.assertRaises(WasteError):
            self._alert(channel="drone")


class TestFireTriage(_Base):
    def _receipt(self, **kw):
        args = dict(
            receipt_id="ft-1",
            battery_id="bat-1",
            triage_grade="low",
            triage_digest=self.hex("e"),
            issued_by="safety",
            authority_pubkey_hex=_PUBKEY,
            authority_secret=_SEED,
            issued_at=_T0,
            expires_at=_T1,
        )
        args.update(kw)
        return battery_fire_triage(**args)

    def test_low_grade_cleared(self):
        log = FireTriageLog()
        log.append(self._receipt())
        v = check_fire_triage(log=log, battery_id="bat-1", now=_T0)
        self.assertTrue(v.allowed)

    def test_high_grade_blocked(self):
        log = FireTriageLog()
        log.append(self._receipt(triage_grade="high"))
        v = check_fire_triage(log=log, battery_id="bat-1", now=_T0)
        self.assertFalse(v.allowed)

    def test_missing_triage_denied(self):
        v = check_fire_triage(log=FireTriageLog(), battery_id="bat-9", now=_T0)
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith("waste.no_fire_triage"))

    def test_bad_grade_rejected(self):
        with self.assertRaises(WasteError):
            self._receipt(triage_grade="unknown")


if __name__ == "__main__":
    unittest.main()
