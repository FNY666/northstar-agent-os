"""Tests for safety_envelope.py (one-hundred-fourth batch).

Deterministic: pinned keys, pinned times. No network, no clock reads.
"""
import hashlib
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key, sign, verify
from canonical_json import jcs_sha256_hex

from safety_envelope import (
    DENY_ACTUATOR_MISMATCH,
    DENY_CHANGE_BAD_SIGNATURE,
    DENY_CHANGE_COOLDOWN,
    DENY_CHANGE_NOT_WIDENING_APPROVED,
    DENY_CHANGE_SELF_APPROVAL,
    DENY_CHANGE_UNKNOWN_AUTHORITY,
    DENY_ENVELOPE_EXPIRED,
    DENY_ENVELOPE_FROM_FUTURE,
    DENY_ENVELOPE_REVOKED,
    DENY_EXCLUSION_ZONE,
    DENY_MALFORMED,
    DENY_NO_ENVELOPE,
    DENY_SPEED_EXCEEDED,
    DENY_TORQUE_EXCEEDED,
    DENY_UNKNOWN_LIMIT,
    ENVELOPE_DENIED_EVENT,
    ActionVerdict,
    AuthorityRegistry,
    ChangeRequest,
    EnvelopeRegistry,
    SafetyEnvelope,
    SafetyEnvelopeError,
    apply_approved_change,
    check_action_within_envelope,
    envelope_denied_audit_event,
    request_envelope_change,
    run_safety_envelope,
    verify_independence,
    _envelope_payload,
    _validate_limits,
)

NOW = 1_700_000_000

AUTH1_SEC = hashlib.sha256(b"test-safety/auth1").digest()
AUTH2_SEC = hashlib.sha256(b"test-safety/auth2").digest()
ROGUE_SEC = hashlib.sha256(b"test-safety/rogue").digest()
AUTH1_PUB = public_key(AUTH1_SEC)
AUTH2_PUB = public_key(AUTH2_SEC)

LIMITS = {
    "max_torque_Nm": 50.0,
    "max_speed_mps": 2.0,
    "exclusion_zones": ["zone-core"],
}


def _authorities():
    a = AuthorityRegistry()
    a.register("op-alice", AUTH1_PUB)
    a.register("op-bob", AUTH2_PUB)
    return a


def _arm(registry, eid="env-1", limits=None, by="op-alice", sec=AUTH1_SEC,
         armed_at=NOW - 100, expires_at=NOW + 3600, prev_hash=""):
    lim = limits if limits is not None else dict(LIMITS)
    payload = _envelope_payload(
        envelope_id=eid, actuator_id="arm/a", hard_limits=_validate_limits(lim),
        armed_by=by, armed_at=armed_at, expires_at=expires_at, prev_hash=prev_hash,
    )
    digest = jcs_sha256_hex(payload)
    return registry.arm_envelope(
        envelope_id=eid, actuator_id="arm/a", hard_limits=lim, armed_by=by,
        armed_at=armed_at, expires_at=expires_at,
        signature=sign(sec, digest.encode("utf-8")), prev_hash=prev_hash,
    )


def _act(eid, **params):
    return {"envelope_id": eid, "actuator_id": "arm/a", "params": dict(params)}


class TestLimitsValidation(unittest.TestCase):
    def test_rejects_unknown_limit_kind(self):
        with self.assertRaises(SafetyEnvelopeError):
            _validate_limits({"max_torque_Nm": 1.0, "laser_W": 5.0})

    def test_rejects_empty_limits(self):
        with self.assertRaises(SafetyEnvelopeError):
            _validate_limits({})

    def test_rejects_negative_torque(self):
        with self.assertRaises(SafetyEnvelopeError):
            _validate_limits({"max_torque_Nm": -1.0})

    def test_sorts_exclusion_zones(self):
        out = _validate_limits({"exclusion_zones": ["b", "a", "a"]})
        self.assertEqual(out["exclusion_zones"], ["a", "b"])


class TestArming(unittest.TestCase):
    def test_agent_cannot_self_issue(self):
        registry = EnvelopeRegistry(_authorities())
        with self.assertRaises(SafetyEnvelopeError):
            _arm(registry, eid="rogue", by="agent-7", sec=ROGUE_SEC)

    def test_bad_signature_refused(self):
        registry = EnvelopeRegistry(_authorities())
        payload = _envelope_payload(
            envelope_id="e", actuator_id="arm/a", hard_limits=_validate_limits(LIMITS),
            armed_by="op-alice", armed_at=NOW - 10, expires_at=NOW + 100, prev_hash="",
        )
        digest = jcs_sha256_hex(payload)
        with self.assertRaises(SafetyEnvelopeError):
            registry.arm_envelope(
                envelope_id="e", actuator_id="arm/a", hard_limits=dict(LIMITS),
                armed_by="op-alice", armed_at=NOW - 10, expires_at=NOW + 100,
                signature=sign(AUTH2_SEC, digest.encode("utf-8")),
            )

    def test_envelope_digest_verifies(self):
        registry = EnvelopeRegistry(_authorities())
        env = _arm(registry)
        ok, reason = registry.verify_envelope(env)
        self.assertTrue(ok, reason)


class TestGate(unittest.TestCase):
    def test_within_limits_allowed(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        v = check_action_within_envelope(
            action=_act("env-1", torque_Nm=10.0, speed_mps=1.0,
                       target_zone="zone-lab"),
            registry=registry, now=NOW)
        self.assertTrue(v.allowed)
        self.assertEqual(v.reason, "allowed")

    def test_torque_exceeded_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        v = check_action_within_envelope(
            action=_act("env-1", torque_Nm=999.0), registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_TORQUE_EXCEEDED)
        self.assertFalse(v.allowed)

    def test_speed_exceeded_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        v = check_action_within_envelope(
            action=_act("env-1", speed_mps=9.0), registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_SPEED_EXCEEDED)

    def test_exclusion_zone_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        v = check_action_within_envelope(
            action=_act("env-1", target_zone="zone-core"),
            registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_EXCLUSION_ZONE)

    def test_unknown_envelope_denies(self):
        registry = EnvelopeRegistry(_authorities())
        v = check_action_within_envelope(
            action=_act("ghost", torque_Nm=1.0), registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_NO_ENVELOPE)

    def test_revoked_envelope_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        registry.revoke("env-1")
        v = check_action_within_envelope(
            action=_act("env-1", torque_Nm=1.0), registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_ENVELOPE_REVOKED)

    def test_expired_envelope_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry, armed_at=NOW - 7200, expires_at=NOW - 5)
        v = check_action_within_envelope(
            action=_act("env-1", torque_Nm=1.0), registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_ENVELOPE_EXPIRED)

    def test_envelope_from_future_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry, armed_at=NOW + 60, expires_at=NOW + 3600)
        v = check_action_within_envelope(
            action=_act("env-1", torque_Nm=1.0), registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_ENVELOPE_FROM_FUTURE)

    def test_actuator_mismatch_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        action = {"envelope_id": "env-1", "actuator_id": "arm/OTHER",
                  "params": {"torque_Nm": 1.0}}
        v = check_action_within_envelope(action=action, registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_ACTUATOR_MISMATCH)

    def test_unknown_param_denies(self):
        registry = EnvelopeRegistry(_authorities())
        _arm(registry)
        v = check_action_within_envelope(
            action=_act("env-1", torque_Nm=1.0, laser_W=3.0),
            registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_UNKNOWN_LIMIT)

    def test_malformed_action_denies(self):
        registry = EnvelopeRegistry(_authorities())
        v = check_action_within_envelope(
            action={"envelope_id": "env-1"}, registry=registry, now=NOW)
        self.assertEqual(v.reason, DENY_MALFORMED)

    def test_audit_event_shape(self):
        ev = envelope_denied_audit_event(
            envelope_id="env-1", reason=DENY_TORQUE_EXCEEDED, action_digest="ab" * 32)
        self.assertEqual(ev["event"], ENVELOPE_DENIED_EVENT)
        self.assertEqual(ev["reason"], DENY_TORQUE_EXCEEDED)


class TestChanges(unittest.TestCase):
    def test_narrowing_fast_path(self):
        authorities = _authorities()
        registry = EnvelopeRegistry(authorities)
        env = _arm(registry)
        req, disp = request_envelope_change(
            request_id="r1", envelope=env,
            proposed_limits={"max_torque_Nm": 10.0, "max_speed_mps": 1.0,
                             "exclusion_zones": ["zone-core", "zone-x"]},
            requested_by="op-alice", requested_at=NOW - 10,
            authorities=authorities)
        self.assertEqual(disp, "narrowing: applied")
        self.assertEqual(req.approved_by, "op-alice")
        self.assertEqual(req.prev_hash, env.envelope_digest)

    def test_widening_needs_second_authority(self):
        authorities = _authorities()
        registry = EnvelopeRegistry(authorities)
        env = _arm(registry)
        req, disp = request_envelope_change(
            request_id="r2", envelope=env,
            proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                             "exclusion_zones": ["zone-core"]},
            requested_by="op-alice", requested_at=NOW - 10,
            authorities=authorities)
        self.assertIn("awaiting second-authority", disp)
        self.assertEqual(req.approved_by, "")

    def test_widening_self_approval_denied(self):
        authorities = _authorities()
        registry = EnvelopeRegistry(authorities)
        env = _arm(registry)
        _req, disp = request_envelope_change(
            request_id="r3", envelope=env,
            proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                             "exclusion_zones": ["zone-core"]},
            requested_by="op-alice", requested_at=NOW - 10,
            approved_by="op-alice", approval_signature=b"\x00" * 64,
            authorities=authorities)
        self.assertEqual(disp, DENY_CHANGE_SELF_APPROVAL)

    def test_widening_bad_signature_denied(self):
        authorities = _authorities()
        registry = EnvelopeRegistry(authorities)
        env = _arm(registry)
        _req, disp = request_envelope_change(
            request_id="r4", envelope=env,
            proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                             "exclusion_zones": ["zone-core"]},
            requested_by="op-alice", requested_at=NOW - 10,
            approved_by="op-bob", approval_signature=b"\x00" * 64,
            authorities=authorities)
        self.assertEqual(disp, DENY_CHANGE_BAD_SIGNATURE)

    def test_apply_before_cooldown_denied(self):
        authorities = _authorities()
        registry = EnvelopeRegistry(authorities)
        env = _arm(registry)
        msg = jcs_sha256_hex({
            "request_id": "r5", "envelope_id": env.envelope_id,
            "proposed_limits": {"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                                "exclusion_zones": ["zone-core"]},
            "requested_by": "op-alice", "requested_at": NOW - 100,
        }).encode("utf-8")
        req, _ = request_envelope_change(
            request_id="r5", envelope=env,
            proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                             "exclusion_zones": ["zone-core"]},
            requested_by="op-alice", requested_at=NOW - 100,
            approved_by="op-bob", approval_signature=sign(AUTH2_SEC, msg),
            authorities=authorities)
        new_env, reason = apply_approved_change(
            request=req, registry=registry, cooldown_s=3600, now=NOW)
        self.assertIsNone(new_env)
        self.assertEqual(reason, DENY_CHANGE_COOLDOWN)

    def test_apply_unapproved_denied(self):
        authorities = _authorities()
        registry = EnvelopeRegistry(authorities)
        env = _arm(registry)
        req, _ = request_envelope_change(
            request_id="r6", envelope=env,
            proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                             "exclusion_zones": ["zone-core"]},
            requested_by="op-alice", requested_at=NOW - 10,
            authorities=authorities)
        new_env, reason = apply_approved_change(
            request=req, registry=registry, cooldown_s=0, now=NOW)
        self.assertIsNone(new_env)
        self.assertEqual(reason, DENY_CHANGE_NOT_WIDENING_APPROVED)


class TestIndependence(unittest.TestCase):
    def test_probe_passes(self):
        ok, reason = verify_independence()
        self.assertTrue(ok, reason)

    def test_bench_corpus_holds(self):
        metrics = run_safety_envelope()
        self.assertEqual(metrics["n_scenarios"], 12)
        self.assertEqual(metrics["mismatches"], [])
        self.assertEqual(metrics["allowed_ids"], [
            "allow_cooldown_elapsed_widening",
            "allow_narrowed_envelope",
            "allow_within_limits",
        ])


if __name__ == "__main__":
    unittest.main()
