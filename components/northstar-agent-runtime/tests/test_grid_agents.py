"""Tests for grid_agents.py (one-hundred-twenty-eighth batch).

Deterministic: pinned keys, pinned times. No network, no clock reads.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key, sign

from grid_agents import (
    DENY_BLACKOUT_CLOCK_MISSED,
    DENY_BLACKOUT_DUPLICATE,
    DENY_CURTAILMENT_REFUSAL,
    DENY_ENVELOPE_EXPIRED,
    DENY_NUCLEAR_CONTROL,
    DENY_OUT_OF_ENVELOPE,
    DENY_POWER_RESONANCE_RISK,
    DENY_SAFETY_COMPONENT_UNREGISTERED,
    DENY_STALE_FORECAST,
    DENY_UNBOUND_DISPATCH,
    DENY_UNREPORTED_BLACKOUT,
    DENY_UNVERIFIABLE_SAFETY_CLASS,
    AuthorityRegistry,
    BlackoutRegistry,
    ControlEnvelopeRegistry,
    CurtailmentContractRegistry,
    ForecastRegistry,
    GridAgentsError,
    NuclearGate,
    SafetyClassRegistry,
    WorkloadPowerScreen,
    issue_curtailment_order,
    grid_audit_event,
)
from canonical_json import jcs_sha256_hex

AUTH_SEC = b"authority-seed-00000000000000001"  # 32 bytes
AUTH2_SEC = b"authority-seed-00000000000000002"
AUTH_PUB = public_key(AUTH_SEC)
AUTH2_PUB = public_key(AUTH2_SEC)
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
DAY = 86_400


def _authorities() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("op-alice", AUTH_PUB)
    reg.register("op-bob", AUTH2_PUB)
    return reg


def _sign_env(envelope_id, operator_id, scopes, modes, issued_by,
              issued_at, expires_at, prev_hash="genesis"):
    payload = {
        "schema_version": "northstar.grid-agents.v1",
        "envelope_id": envelope_id,
        "operator_id": operator_id,
        "scope_kinds": sorted(scopes),
        "autonomy_modes": sorted(modes),
        "issued_by": issued_by,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "prev_hash": prev_hash,
    }
    key = AUTH_SEC if issued_by == "op-alice" else AUTH2_SEC
    return sign(key, jcs_sha256_hex(payload).encode("utf-8"))


class SafetyClassGateTest(unittest.TestCase):
    def test_undeclared_fails_closed(self) -> None:
        reg = SafetyClassRegistry()
        v = reg.safety_component_gate("sys-1")
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNVERIFIABLE_SAFETY_CLASS, v.reason)

    def test_optimization_without_boundary_fails(self) -> None:
        reg = SafetyClassRegistry()
        reg.declare(system_id="sys-1", safety_class="non_safety_optimization",
                    declared_at=T0)
        v = reg.safety_component_gate("sys-1")
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNVERIFIABLE_SAFETY_CLASS, v.reason)

    def test_optimization_with_boundary_allows(self) -> None:
        reg = SafetyClassRegistry()
        decl = reg.declare(system_id="sys-1", safety_class="non_safety_optimization",
                           declared_boundary_digest=HEX64, declared_at=T0)
        v = reg.safety_component_gate("sys-1")
        self.assertTrue(v.allowed)
        self.assertEqual(v.receipt_digest, decl.declaration_digest)

    def test_safety_component_without_registration_fails(self) -> None:
        reg = SafetyClassRegistry()
        reg.declare(system_id="sys-2", safety_class="safety_component",
                    declared_at=T0)
        v = reg.safety_component_gate("sys-2")
        self.assertFalse(v.allowed)
        self.assertIn(DENY_SAFETY_COMPONENT_UNREGISTERED, v.reason)

    def test_safety_component_with_registration_allows(self) -> None:
        reg = SafetyClassRegistry()
        reg.declare(system_id="sys-2", safety_class="safety_component",
                    registration_digest=HEX64_B, declared_at=T0)
        v = reg.safety_component_gate("sys-2")
        self.assertTrue(v.allowed)

    def test_unknown_class_raises(self) -> None:
        reg = SafetyClassRegistry()
        with self.assertRaises(GridAgentsError):
            reg.declare(system_id="x", safety_class="probably_fine", declared_at=T0)


class ControlEnvelopeTest(unittest.TestCase):
    def _env(self, authorities, **kw):
        reg = ControlEnvelopeRegistry(authorities)
        defaults = dict(envelope_id="env-1", operator_id="ops-1",
                        scope_kinds=("vpp_dispatch",), autonomy_modes=("autonomous",),
                        issued_by="op-alice", issued_at=T0, expires_at=T0 + DAY)
        defaults.update(kw)
        scope = sorted(defaults.pop("scope_kinds"))
        modes = sorted(defaults.pop("autonomy_modes"))
        sig = _sign_env(defaults["envelope_id"], defaults["operator_id"],
                        tuple(scope), tuple(modes), defaults["issued_by"],
                        defaults["issued_at"], defaults["expires_at"])
        return reg.issue_envelope(scope_kinds=tuple(scope),
                                  autonomy_modes=tuple(modes),
                                  signature=sig, **defaults), reg

    def test_dispatch_inside_envelope_allows(self) -> None:
        _, reg = self._env(_authorities())
        v = reg.check_dispatch(envelope_id="env-1", action_kind="vpp_dispatch",
                               mode="autonomous", now=T0 + 1)
        self.assertTrue(v.allowed)

    def test_dispatch_outside_scope_denies(self) -> None:
        _, reg = self._env(_authorities())
        v = reg.check_dispatch(envelope_id="env-1", action_kind="transformer_switching",
                               mode="autonomous", now=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_OUT_OF_ENVELOPE, v.reason)

    def test_disallowed_mode_denies(self) -> None:
        _, reg = self._env(_authorities())
        v = reg.check_dispatch(envelope_id="env-1", action_kind="vpp_dispatch",
                               mode="human_on_the_loop", now=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_OUT_OF_ENVELOPE, v.reason)

    def test_expired_envelope_fails_closed(self) -> None:
        _, reg = self._env(_authorities())
        v = reg.check_dispatch(envelope_id="env-1", action_kind="vpp_dispatch",
                               mode="autonomous", now=T0 + DAY + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_ENVELOPE_EXPIRED, v.reason)

    def test_revoked_envelope_fails_closed(self) -> None:
        _, reg = self._env(_authorities())
        reg.revoke("env-1")
        v = reg.check_dispatch(envelope_id="env-1", action_kind="vpp_dispatch",
                               mode="autonomous", now=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertIn("revoked", v.reason)

    def test_self_widening_raises(self) -> None:
        env, reg = self._env(_authorities())
        prev = env.envelope_digest
        sig = _sign_env("env-1", "ops-1", ("vpp_dispatch", "transformer_switching"),
                        ("autonomous",), "op-alice", T0 + 1, T0 + 2 * DAY,
                        prev_hash=prev)
        with self.assertRaises(GridAgentsError):
            reg.request_widen(envelope_id="env-1",
                              new_scope_kinds=("transformer_switching",),
                              requested_by="op-alice", approved_by="op-alice",
                              signature=sig, issued_at=T0 + 1, expires_at=T0 + 2 * DAY)


class ForecastBindingTest(unittest.TestCase):
    def test_unbound_dispatch_denies(self) -> None:
        reg = ForecastRegistry()
        v = reg.check_dispatch_binding(forecast_id=None, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNBOUND_DISPATCH, v.reason)

    def test_unknown_forecast_denies(self) -> None:
        reg = ForecastRegistry()
        v = reg.check_dispatch_binding(forecast_id="nope", now=T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNBOUND_DISPATCH, v.reason)

    def test_fresh_forecast_binding_allows(self) -> None:
        reg = ForecastRegistry()
        receipt = reg.register_forecast(forecast_id="fc-1", forecast_digest=HEX64,
                                        horizon_s=3600, issued_at=T0, issuer="meteo")
        v = reg.check_dispatch_binding(forecast_id="fc-1", now=T0 + 100)
        self.assertTrue(v.allowed)
        self.assertEqual(v.receipt_digest, receipt.receipt_digest)

    def test_stale_forecast_denies(self) -> None:
        reg = ForecastRegistry()
        reg.register_forecast(forecast_id="fc-1", forecast_digest=HEX64,
                              horizon_s=3600, issued_at=T0, issuer="meteo")
        v = reg.check_dispatch_binding(forecast_id="fc-1", now=T0 + 3601)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_STALE_FORECAST, v.reason)


class WorkloadPowerScreenTest(unittest.TestCase):
    def test_unscreened_quarantines(self) -> None:
        screen = WorkloadPowerScreen()
        v = screen.screen_workload(workload_id="wl-1", peak_mw=120,
                                   fluctuation_class="unscreened")
        self.assertFalse(v.allowed)
        self.assertIn(DENY_POWER_RESONANCE_RISK, v.reason)

    def test_stable_allows(self) -> None:
        screen = WorkloadPowerScreen()
        v = screen.screen_workload(workload_id="wl-2", peak_mw=120,
                                   fluctuation_class="stable")
        self.assertTrue(v.allowed)

    def test_unknown_class_raises(self) -> None:
        screen = WorkloadPowerScreen()
        with self.assertRaises(GridAgentsError):
            screen.screen_workload(workload_id="wl-3", peak_mw=10,
                                   fluctuation_class="probably_smooth")


class CurtailmentContractTest(unittest.TestCase):
    def _contract(self, registry=None):
        authorities = _authorities() if registry is None else registry
        reg = CurtailmentContractRegistry(authorities)
        payload = {
            "schema_version": "northstar.grid-agents.v1",
            "contract_id": "ct-1",
            "workload_id": "wl-1",
            "curtailment_authority_id": "op-alice",
            "cap_rule_digest": HEX64,
            "issued_by": "op-bob",
            "issued_at": T0,
            "prev_hash": "genesis",
        }
        sig = sign(AUTH2_SEC, jcs_sha256_hex(payload).encode("utf-8"))
        return reg.issue_contract(contract_id="ct-1", workload_id="wl-1",
                                  curtailment_authority_id="op-alice",
                                  cap_rule_digest=HEX64, issued_by="op-bob",
                                  issued_at=T0, signature=sig), reg

    def _order(self, authorities, active=True):
        payload = {
            "schema_version": "northstar.grid-agents.v1",
            "order_id": "ord-1",
            "grid_region": "PJM",
            "start_unix": T0 if active else T0 + 2 * DAY,
            "end_unix": T0 + DAY if active else T0 + 3 * DAY,
            "issued_by": "op-alice",
            "issued_at": T0,
        }
        sig = sign(AUTH_SEC, jcs_sha256_hex(payload).encode("utf-8"))
        return issue_curtailment_order(
            authorities, order_id="ord-1", grid_region="PJM",
            start_unix=payload["start_unix"], end_unix=payload["end_unix"],
            issued_by="op-alice", issued_at=T0, signature=sig)

    def test_refusal_during_active_order_denies(self) -> None:
        _, reg = self._contract()
        order = self._order(_authorities(), active=True)
        v = reg.check_curtailment(workload_id="wl-1", order=order,
                                  complied=False, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_CURTAILMENT_REFUSAL, v.reason)

    def test_compliance_allows(self) -> None:
        _, reg = self._contract()
        order = self._order(_authorities(), active=True)
        v = reg.check_curtailment(workload_id="wl-1", order=order,
                                  complied=True, now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_no_contract_denies(self) -> None:
        _, reg = self._contract()
        order = self._order(_authorities(), active=True)
        v = reg.check_curtailment(workload_id="wl-naked", order=order,
                                  complied=True, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_CURTAILMENT_REFUSAL, v.reason)


class NuclearGateTest(unittest.TestCase):
    def _grant(self, gate):
        payload = {
            "schema_version": "northstar.grid-agents.v1",
            "system_id": "npp-1",
            "control_scope_digest": HEX64,
            "granted_by": "op-alice",
            "granted_at": T0,
            "expires_at": T0 + DAY,
        }
        sig = sign(AUTH_SEC, jcs_sha256_hex(payload).encode("utf-8"))
        return gate.grant_control(system_id="npp-1", control_scope_digest=HEX64,
                                 granted_by="op-alice", granted_at=T0,
                                 expires_at=T0 + DAY, signature=sig)

    def test_advisory_allows_without_grant(self) -> None:
        gate = NuclearGate(_authorities())
        v = gate.check_action(system_id="npp-1", mode="advisory", now=T0)
        self.assertTrue(v.allowed)

    def test_control_without_grant_denies(self) -> None:
        gate = NuclearGate(_authorities())
        v = gate.check_action(system_id="npp-1", mode="control", now=T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_NUCLEAR_CONTROL, v.reason)

    def test_control_with_grant_allows(self) -> None:
        gate = NuclearGate(_authorities())
        digest = self._grant(gate)
        v = gate.check_action(system_id="npp-1", mode="control",
                              control_scope_digest=HEX64, now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.receipt_digest, digest)

    def test_control_scope_mismatch_denies(self) -> None:
        gate = NuclearGate(_authorities())
        self._grant(gate)
        v = gate.check_action(system_id="npp-1", mode="control",
                              control_scope_digest=HEX64_B, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_NUCLEAR_CONTROL, v.reason)


class BlackoutRegistryTest(unittest.TestCase):
    def test_missing_timeline_is_unreported(self) -> None:
        reg = BlackoutRegistry()
        v = reg.file_blackout(incident_id="bo-1", system_id="tso-1",
                              timeline_digest=None, detected_at=T0,
                              reported_at=T0 + 100, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNREPORTED_BLACKOUT, v.reason)

    def test_fresh_filing_with_timeline_allows(self) -> None:
        reg = BlackoutRegistry()
        v = reg.file_blackout(incident_id="bo-1", system_id="tso-1",
                              timeline_digest=HEX64, detected_at=T0,
                              reported_at=T0 + 100, now=T0 + 100)
        self.assertTrue(v.allowed)
        self.assertIsNotNone(v.receipt)
        self.assertFalse(v.receipt.clock_missed)

    def test_late_filing_records_and_refuses(self) -> None:
        reg = BlackoutRegistry()
        v = reg.file_blackout(incident_id="bo-1", system_id="tso-1",
                              timeline_digest=HEX64, detected_at=T0,
                              reported_at=T0 + 2 * DAY + 1, now=T0 + 2 * DAY + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_BLACKOUT_CLOCK_MISSED, v.reason)
        self.assertTrue(v.receipt.clock_missed)

    def test_duplicate_denies(self) -> None:
        reg = BlackoutRegistry()
        reg.file_blackout(incident_id="bo-1", system_id="tso-1",
                          timeline_digest=HEX64, detected_at=T0,
                          reported_at=T0 + 100, now=T0 + 100)
        v = reg.file_blackout(incident_id="bo-1", system_id="tso-1",
                              timeline_digest=HEX64, detected_at=T0,
                              reported_at=T0 + 100, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_BLACKOUT_DUPLICATE, v.reason)

    def test_future_detected_at_raises(self) -> None:
        reg = BlackoutRegistry()
        with self.assertRaises(GridAgentsError):
            reg.file_blackout(incident_id="bo-1", system_id="tso-1",
                              timeline_digest=HEX64, detected_at=T0 + 100,
                              reported_at=T0 + 100, now=T0)


class AuditEventTest(unittest.TestCase):
    def test_audit_event_shape(self) -> None:
        ev = grid_audit_event("grid:out_of_envelope", "scope breach")
        self.assertEqual(ev["event"], "grid.audit")
        self.assertEqual(ev["code"], "grid:out_of_envelope")


if __name__ == "__main__":
    unittest.main()
