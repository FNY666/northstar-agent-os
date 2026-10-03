"""Tests for orbital_agents.py (one-hundred-thirty-fourth batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

import ed25519

from orbital_agents import (
    ORBITAL_SCHEMA_VERSION,
    WARNING_FATIGUE_THRESHOLD,
    CapabilityDeclaration,
    ConjunctionRegistry,
    CounterspaceRegistry,
    LiabilityRegistry,
    OrbitalError,
    OrbitalVerdict,
    STMRegistry,
    check_debris_budget,
    check_maneuver,
    check_onboard_decision,
    conjunction_receipt,
    counterspace_transparency,
    dual_use_rpo_gate,
    liability_pin,
    maneuver_authorization_envelope,
    megaconstellation_debris_budget,
    onboard_model_receipt,
    orbital_audit_event,
    stm_data_receipt,
)

T0 = 1_700_000_000
AUTH = bytes([3]) * 32
AUTH_PUB = ed25519.public_key(AUTH).hex()
OTHER = bytes([7]) * 32
OTHER_PUB = ed25519.public_key(OTHER).hex()
D1 = "ab" * 32
D2 = "cd" * 32
D3 = "ef" * 32


def _conj(warning_id="w-1", pair="SAT-A/SAT-B", prev="genesis"):
    return conjunction_receipt(
        receipt_id="c-" + warning_id,
        warning_id=warning_id,
        conjunction_digest=D1,
        uncertainty_km=0.5,
        warned_at=T0,
        ttl_s=3600,
        object_pair=pair,
        issued_by="stm-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
        prev_digest=prev,
    )


def _envelope(max_dv=5.0):
    return maneuver_authorization_envelope(
        envelope_id="env-1",
        max_dv_ms=max_dv,
        valid_from=T0,
        valid_to=T0 + 7200,
        issued_by="flight-dynamics",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
    )


def _stm(data_id="stm-1"):
    return stm_data_receipt(
        receipt_id="s-" + data_id,
        data_id=data_id,
        data_digest=D2,
        uncertainty_km=1.2,
        observed_at=T0,
        ttl_s=1800,
        source="tracss-pilot",
        issued_by="stm-ops",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTH,
    )


class ConjunctionTests(unittest.TestCase):
    def test_allow_fresh_warning(self):
        reg = ConjunctionRegistry()
        reg.register(_conj())
        v = reg.check_maneuver(
            warning_id="w-1", dv_ms=2.0, maneuver_at=T0 + 100, now=T0 + 200
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "conjunction_fresh")

    def test_deny_stale_warning(self):
        reg = ConjunctionRegistry()
        reg.register(_conj())
        v = reg.check_maneuver(
            warning_id="w-1", dv_ms=2.0, maneuver_at=T0 + 7200, now=T0 + 7300
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:stale_conjunction", v.reason)

    def test_deny_unknown_warning(self):
        reg = ConjunctionRegistry()
        v = reg.check_maneuver(
            warning_id="w-ghost", dv_ms=1.0, maneuver_at=T0, now=T0
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:unknown_conjunction", v.reason)

    def test_warning_fatigue_trips(self):
        reg = ConjunctionRegistry()
        reg.register(_conj())
        for _ in range(WARNING_FATIGUE_THRESHOLD):
            v = reg.check_maneuver(
                warning_id="w-1", dv_ms=1.0, maneuver_at=T0 + 10, now=T0 + 20
            )
            self.assertTrue(v.allowed)
        v = reg.check_maneuver(
            warning_id="w-1", dv_ms=1.0, maneuver_at=T0 + 10, now=T0 + 20
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:warning_fatigue", v.reason)

    def test_ground_revalidation_resets_fatigue(self):
        reg = ConjunctionRegistry()
        reg.register(_conj())
        for _ in range(WARNING_FATIGUE_THRESHOLD):
            reg.check_maneuver(
                warning_id="w-1", dv_ms=1.0, maneuver_at=T0 + 10, now=T0 + 20
            )
        reg.ground_revalidation("SAT-A/SAT-B")
        v = reg.check_maneuver(
            warning_id="w-1", dv_ms=1.0, maneuver_at=T0 + 10, now=T0 + 20
        )
        self.assertTrue(v.allowed)

    def test_chain_break_raises(self):
        reg = ConjunctionRegistry()
        reg.register(_conj())
        bad = _conj(warning_id="w-2", prev="00" * 32)
        with self.assertRaises(OrbitalError):
            reg.register(bad)

    def test_malformed_input_raises(self):
        with self.assertRaises(OrbitalError):
            conjunction_receipt(
                receipt_id="c-x",
                warning_id="w-x",
                conjunction_digest="nothex",
                uncertainty_km=0.5,
                warned_at=T0,
                ttl_s=3600,
                object_pair="A/B",
                issued_by="ops",
                authority_pubkey_hex=AUTH_PUB,
                authority_secret=AUTH,
            )


class EnvelopeTests(unittest.TestCase):
    def test_allow_within_envelope(self):
        env = _envelope()
        v = check_maneuver(env, dv_ms=3.0, at=T0 + 100, now=T0 + 200)
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "within_envelope")

    def test_deny_dv_breach(self):
        env = _envelope(max_dv=5.0)
        v = check_maneuver(env, dv_ms=50.0, at=T0 + 100, now=T0 + 200)
        self.assertFalse(v.allowed)
        self.assertIn("orbital:envelope_breach", v.reason)

    def test_deny_window_breach(self):
        env = _envelope()
        v = check_maneuver(env, dv_ms=1.0, at=T0 + 99999, now=T0 + 100000)
        self.assertFalse(v.allowed)
        self.assertIn("orbital:envelope_breach", v.reason)

    def test_deny_tampered_signature(self):
        env = _envelope()
        tampered = maneuver_authorization_envelope(
            envelope_id="env-1",
            max_dv_ms=5.0,
            valid_from=T0,
            valid_to=T0 + 7200,
            issued_by="flight-dynamics",
            authority_pubkey_hex=OTHER_PUB,
            authority_secret=OTHER,
        )
        v = check_maneuver(
            tampered.__class__(
                **{**tampered.__dict__, "authority_pubkey_hex": AUTH_PUB}
            ),
            dv_ms=1.0,
            at=T0 + 100,
            now=T0 + 200,
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:signature_invalid", v.reason)


class STMTests(unittest.TestCase):
    def test_allow_bound_stm(self):
        reg = STMRegistry()
        reg.register(_stm())
        v = reg.check_bound(data_id="stm-1", at=T0 + 100, now=T0 + 200)
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "stm_bound")

    def test_unbound_stm_non_authoritative(self):
        reg = STMRegistry()
        v = reg.check_bound(data_id="stm-ghost", at=T0, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")
        self.assertIn("orbital:unbound_stm", v.reason)

    def test_deny_stale_stm(self):
        reg = STMRegistry()
        reg.register(_stm())
        v = reg.check_bound(data_id="stm-1", at=T0 + 99999, now=T0 + 100000)
        self.assertFalse(v.allowed)
        self.assertIn("orbital:stale_stm", v.reason)


class RPOTests(unittest.TestCase):
    def test_allow_cooperative_consented(self):
        v = dual_use_rpo_gate(
            operation_id="op-1",
            target_id="SAT-FRIENDLY",
            cooperative=True,
            consent_digest=D3,
            approach_profile={"range_km": 2.0},
            created_unix=T0,
        )
        self.assertTrue(v.allowed)

    def test_deny_cooperative_without_consent(self):
        v = dual_use_rpo_gate(
            operation_id="op-1",
            target_id="SAT-FRIENDLY",
            cooperative=True,
            consent_digest=None,
            approach_profile={},
            created_unix=T0,
        )
        self.assertFalse(v.allowed)

    def test_noncooperative_clean_screen_needs_human(self):
        v = dual_use_rpo_gate(
            operation_id="op-2",
            target_id="SAT-UNKNOWN",
            cooperative=False,
            consent_digest=None,
            approach_profile={"range_km": 1.5, "purpose": "inspection"},
            created_unix=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")
        self.assertIn("orbital:rpo_human_review", v.reason)

    def test_noncooperative_watchlist_hit_escalates(self):
        v = dual_use_rpo_gate(
            operation_id="op-3",
            target_id="SAT-UNKNOWN",
            cooperative=False,
            consent_digest=None,
            approach_profile={"payload": "toxin canister deployment"},
            created_unix=T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:rpo_escalation", v.reason)


class DebrisBudgetTests(unittest.TestCase):
    def _budget(self, planned=1000, max_objects=5000):
        return megaconstellation_debris_budget(
            receipt_id="db-1",
            constellation_id="MEGA-1",
            max_objects=max_objects,
            planned_objects=planned,
            expected_debris_objects=12,
            issued_by="licensing",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTH,
        )

    def test_allow_within_budget(self):
        v = check_debris_budget(self._budget(), planned_objects=1000, now=T0)
        self.assertTrue(v.allowed)

    def test_deny_over_budget(self):
        v = check_debris_budget(self._budget(), planned_objects=9000, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("orbital:debris_over_budget", v.reason)


class OnboardModelTests(unittest.TestCase):
    def _model(self):
        return onboard_model_receipt(
            receipt_id="om-1",
            model_id="moi-1a-nav",
            autonomy_boundary=("station_keeping", "collision_avoidance"),
            issued_by="mission-ops",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTH,
        )

    def test_allow_within_boundary(self):
        v = check_onboard_decision(
            self._model(), decision_class="collision_avoidance", now=T0
        )
        self.assertTrue(v.allowed)

    def test_deny_autonomy_breach(self):
        v = check_onboard_decision(
            self._model(), decision_class="rpo_approach", now=T0
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:autonomy_breach", v.reason)

    def test_unknown_decision_class_rejected_at_issue(self):
        with self.assertRaises(OrbitalError):
            onboard_model_receipt(
                receipt_id="om-x",
                model_id="m-x",
                autonomy_boundary=("mind_control",),
                issued_by="ops",
                authority_pubkey_hex=AUTH_PUB,
                authority_secret=AUTH,
            )


class CounterspaceTests(unittest.TestCase):
    def _declare(self, system_id="SYS-1", cap="inspection", prev="genesis"):
        return counterspace_transparency(
            receipt_id="cs-" + system_id + "-" + cap,
            system_id=system_id,
            capability_class=cap,
            declared_at=T0,
            issued_by="space-command",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTH,
            prev_digest=prev,
        )

    def test_allow_declared_capability(self):
        reg = CounterspaceRegistry()
        reg.declare(self._declare())
        v = reg.check_capability(
            system_id="SYS-1", observed_capability_class="inspection", now=T0
        )
        self.assertTrue(v.allowed)

    def test_deny_undeclared_capability(self):
        reg = CounterspaceRegistry()
        reg.declare(self._declare())
        v = reg.check_capability(
            system_id="SYS-1",
            observed_capability_class="electronic_warfare",
            now=T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:undeclared_capability", v.reason)
        self.assertEqual(
            v.audit_event["event"], "orbital.counterspace_declared"
        )

    def test_unknown_capability_class_rejected(self):
        with self.assertRaises(OrbitalError):
            counterspace_transparency(
                receipt_id="cs-x",
                system_id="SYS-X",
                capability_class="death_ray",
                declared_at=T0,
                issued_by="ops",
                authority_pubkey_hex=AUTH_PUB,
                authority_secret=AUTH,
            )


class LiabilityTests(unittest.TestCase):
    def _pin(self, object_id="OBJ-1", deadline=T0 + 86400, prev="genesis"):
        return liability_pin(
            receipt_id="lp-" + object_id,
            object_id=object_id,
            payer="operator-corp",
            cleanup_party="debris-removal-co",
            deorbit_deadline=deadline,
            issued_by="licensing",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTH,
            prev_digest=prev,
        )

    def test_allow_deorbited(self):
        reg = LiabilityRegistry()
        v = reg.check_deorbit(
            object_id="OBJ-9", at=T0, still_in_orbit=False, now=T0
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "deorbited")

    def test_allow_deadline_not_reached(self):
        reg = LiabilityRegistry()
        reg.register(self._pin())
        v = reg.check_deorbit(
            object_id="OBJ-1", at=T0, still_in_orbit=True, now=T0
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "deadline_not_reached")

    def test_allow_missed_deadline_with_pin(self):
        reg = LiabilityRegistry()
        reg.register(self._pin())
        v = reg.check_deorbit(
            object_id="OBJ-1", at=T0 + 86400 * 2, still_in_orbit=True,
            now=T0 + 86400 * 2,
        )
        self.assertTrue(v.allowed)
        self.assertIn("liability_pinned", v.reason)
        self.assertEqual(v.audit_event["payer"], "operator-corp")

    def test_deny_no_pin(self):
        reg = LiabilityRegistry()
        v = reg.check_deorbit(
            object_id="OBJ-GHOST", at=T0, still_in_orbit=True, now=T0
        )
        self.assertFalse(v.allowed)
        self.assertIn("orbital:no_liability_pin", v.reason)


class AuditEventTests(unittest.TestCase):
    def test_audit_event_shape(self):
        e = orbital_audit_event(
            action="orbital.maneuver_checked",
            allowed=True,
            reason="within_envelope",
            created_unix=T0,
            warning_id="w-1",
        )
        self.assertEqual(e["event"], "orbital.maneuver_checked")
        self.assertTrue(e["allowed"])
        self.assertEqual(e["created_unix"], T0)


if __name__ == "__main__":
    unittest.main()
