"""Tests for capability passports: minting, mandatory-intersection
delegation, real revocation, and chain verification.

Covers: passport mint/verify (format, signature, expiry, revocation),
the mandatory capability intersection (escalation refused at mint,
constraints narrowed delegator-wins), tool-use checks, delegation chains
(continuity, depth ceiling, attenuation invariant re-checked), the
passport_for_identity wiring into agent_identity, and audit anchoring.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from audit_chain import chain_records, verify_lines
from agent_identity import IdentityIssuer as AgentIdentityIssuer, did_of

from passport import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_PASSPORT_TTL_SECONDS,
    PASSPORT_VERSION,
    TRUST_LEVELS,
    CapabilityPassport,
    PassportError,
    PassportIssuer,
    PassportVerdict,
    RevocationList,
    capabilities_within,
    check_tool_use,
    delegate_passport,
    intersect_capabilities,
    passport_audit_events,
    passport_for_identity,
    verify_passport,
    verify_passport_chain,
)

NOW = "2026-10-04T02:30:00Z"
LATER = "2026-10-04T03:30:00Z"  # NOW + 3600s


def _secret(label: str) -> bytes:
    import hashlib

    return hashlib.sha256(f"northstar-test-passport:{label}".encode()).digest()


def _issuer() -> PassportIssuer:
    return PassportIssuer(_secret("authority"))


def _caps() -> dict:
    return {
        "database_read": {
            "allowed": True,
            "constraints": {"allowed_tables": ["customers", "orders", "payments"]},
        },
        "files_read": {"allowed": True, "constraints": {"max_rows": 1000}},
    }


def _mint(issuer=None, **kw) -> CapabilityPassport:
    issuer = issuer or _issuer()
    args = {
        "sub": "worker-1",
        "public_key_hex": ed25519.public_key(_secret("worker-1")).hex(),
        "capabilities": _caps(),
        "time_iso": NOW,
    }
    args.update(kw)
    return issuer.mint(**args)


class MintTests(unittest.TestCase):
    def test_mint_shape(self):
        p = _mint()
        self.assertTrue(p.jti.startswith("pp-"))
        self.assertEqual(p.sub, "worker-1")
        self.assertLess(p.iat, p.exp)
        self.assertEqual(p.delegation_depth, 0)
        self.assertEqual(p.parent_jti, "")
        self.assertEqual(len(bytes.fromhex(p.signature)), 64)

    def test_jti_unique(self):
        self.assertNotEqual(_mint().jti, _mint().jti)

    def test_mint_rejects_empty_subject(self):
        with self.assertRaises(PassportError):
            _mint(sub="  ")

    def test_mint_rejects_no_clock(self):
        with self.assertRaises(PassportError):
            _mint(time_iso="")

    def test_mint_rejects_malformed_time(self):
        with self.assertRaises(PassportError):
            _mint(time_iso="not-a-time")

    def test_mint_rejects_bad_capabilities(self):
        with self.assertRaises(PassportError):
            _mint(capabilities={"tool": {"allowed": "yes"}})
        with self.assertRaises(PassportError):
            _mint(capabilities={})

    def test_mint_rejects_bad_trust_level(self):
        with self.assertRaises(PassportError):
            _mint(trust_level=99)

    def test_verify_ok(self):
        issuer = _issuer()
        p = _mint(issuer)
        v = verify_passport(p, signer_public_key_hex=issuer.public_key_hex, time_iso=NOW)
        self.assertTrue(v.allowed, v.reason)

    def test_verify_wrong_signer(self):
        p = _mint()
        other = PassportIssuer(_secret("other-authority"))
        v = verify_passport(
            p, signer_public_key_hex=other.public_key_hex, time_iso=NOW
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "signature_invalid")


class ExpiryTests(unittest.TestCase):
    def test_expired(self):
        p = _mint(ttl_seconds=60)
        v = verify_passport(
            p, signer_public_key_hex=_issuer().public_key_hex, time_iso=LATER
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "passport_expired")

    def test_expiry_uncheckable_without_time(self):
        p = _mint()
        v = verify_passport(p, signer_public_key_hex=_issuer().public_key_hex)
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "expiry_uncheckable")

    def test_future_iat_rejected(self):
        p = _mint(time_iso=LATER)
        v = verify_passport(
            p, signer_public_key_hex=_issuer().public_key_hex, time_iso=NOW
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "passport_not_yet_valid")

    def test_tampered_exp_detected(self):
        p = _mint(ttl_seconds=60)
        from dataclasses import replace as _replace
        tampered = _replace(p, exp=LATER)
        v = verify_passport(
            tampered, signer_public_key_hex=_issuer().public_key_hex, time_iso=LATER
        )
        # The signature no longer matches the tampered envelope.
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "signature_invalid")


class RevocationTests(unittest.TestCase):
    def test_revoke_is_real(self):
        issuer = _issuer()
        p = _mint(issuer)
        rl = RevocationList()
        self.assertFalse(rl.is_revoked(p.jti))
        rl.revoke(p.jti, reason="key compromise", revoked_at=NOW)
        self.assertTrue(rl.is_revoked(p.jti))
        v = verify_passport(
            p,
            signer_public_key_hex=issuer.public_key_hex,
            time_iso=NOW,
            revocation=rl,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "passport_revoked")

    def test_revoke_idempotent(self):
        rl = RevocationList()
        rl.revoke("pp-abc", reason="x")
        rl.revoke("pp-abc", reason="y")
        self.assertEqual(len(rl), 1)
        self.assertEqual(rl.entry("pp-abc").reason, "x")

    def test_revoke_empty_jti_fails(self):
        with self.assertRaises(PassportError):
            RevocationList().revoke("  ")

    def test_no_revocation_list_means_no_check(self):
        issuer = _issuer()
        p = _mint(issuer)
        v = verify_passport(
            p, signer_public_key_hex=issuer.public_key_hex, time_iso=NOW
        )
        self.assertTrue(v.allowed)


class IntersectionTests(unittest.TestCase):
    def test_intersection_narrows(self):
        delegator = _caps()
        requested = {
            "database_read": {
                "allowed": True,
                "constraints": {"allowed_tables": ["customers"]},
            }
        }
        out = intersect_capabilities(delegator, requested)
        self.assertEqual(
            out["database_read"]["constraints"]["allowed_tables"], ["customers"]
        )
        # files_read was not requested -> not delegated.
        self.assertNotIn("files_read", out)

    def test_intersection_numeric_min(self):
        delegator = {"q": {"allowed": True, "constraints": {"max_rows": 100}}}
        requested = {"q": {"allowed": True, "constraints": {"max_rows": 10}}}
        out = intersect_capabilities(delegator, requested)
        self.assertEqual(out["q"]["constraints"]["max_rows"], 10)

    def test_intersection_requested_denied_skipped(self):
        delegator = _caps()
        requested = {"database_read": {"allowed": False}}
        with self.assertRaises(PassportError):
            intersect_capabilities(delegator, requested)

    def test_intersection_unheld_tool_raises(self):
        with self.assertRaises(PassportError):
            intersect_capabilities(_caps(), {"net_egress": {"allowed": True}})

    def test_intersection_denied_tool_raises(self):
        delegator = {"t": {"allowed": False}}
        with self.assertRaises(PassportError):
            intersect_capabilities(delegator, {"t": {"allowed": True}})

    def test_delegate_narrows_and_signs(self):
        issuer = _issuer()
        parent = _mint(issuer)
        delegator_secret = _secret("worker-1")
        child = delegate_passport(
            parent,
            delegator_secret,
            delegatee_sub="sub-1",
            delegatee_public_key_hex=ed25519.public_key(_secret("sub-1")).hex(),
            requested_capabilities={
                "database_read": {
                    "allowed": True,
                    "constraints": {"allowed_tables": ["customers"]},
                }
            },
            time_iso=NOW,
            purpose="read customer rows",
        )
        self.assertEqual(child.parent_jti, parent.jti)
        self.assertEqual(child.delegation_depth, 1)
        self.assertEqual(
            child.capabilities["database_read"]["constraints"]["allowed_tables"],
            ["customers"],
        )
        self.assertNotIn("files_read", child.capabilities)
        self.assertEqual(child.issued_by, parent.sub)

    def test_delegate_escalation_refused_at_mint(self):
        parent = _mint()
        with self.assertRaises(PassportError):
            delegate_passport(
                parent,
                _secret("worker-1"),
                delegatee_sub="sub-1",
                delegatee_public_key_hex=ed25519.public_key(_secret("sub-1")).hex(),
                requested_capabilities={"admin_write": {"allowed": True}},
                time_iso=NOW,
            )

    def test_child_cannot_outlive_parent(self):
        issuer = _issuer()
        parent = _mint(issuer, ttl_seconds=600)  # expires NOW+600
        child = delegate_passport(
            parent,
            _secret("worker-1"),
            delegatee_sub="sub-1",
            delegatee_public_key_hex=ed25519.public_key(_secret("sub-1")).hex(),
            requested_capabilities={
                "files_read": {"allowed": True, "constraints": {"max_rows": 5}}
            },
            ttl_seconds=3600,  # would outlive the parent
            time_iso=NOW,
        )
        self.assertEqual(child.exp, parent.exp)


class ToolUseTests(unittest.TestCase):
    def test_tool_granted(self):
        issuer = _issuer()
        p = _mint(issuer)
        v = check_tool_use(
            p,
            "database_read",
            signer_public_key_hex=issuer.public_key_hex,
            time_iso=NOW,
        )
        self.assertTrue(v.allowed, v.reason)

    def test_tool_not_granted(self):
        issuer = _issuer()
        p = _mint(issuer)
        v = check_tool_use(
            p,
            "net_egress",
            signer_public_key_hex=issuer.public_key_hex,
            time_iso=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "tool_not_granted")

    def test_tool_use_fails_when_passport_revoked(self):
        issuer = _issuer()
        p = _mint(issuer)
        rl = RevocationList()
        rl.revoke(p.jti, reason="compromise")
        v = check_tool_use(
            p,
            "database_read",
            signer_public_key_hex=issuer.public_key_hex,
            time_iso=NOW,
            revocation=rl,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "passport_revoked")


class ChainTests(unittest.TestCase):
    def _chain(self, n=2):
        issuer = _issuer()
        root = _mint(issuer, sub="root-agent",
                     public_key_hex=ed25519.public_key(_secret("root-agent")).hex())
        hops = [root]
        prev_secret = _secret("root-agent")
        prev = root
        for i in range(1, n + 1):
            label = f"agent-{i}"
            child = delegate_passport(
                prev,
                prev_secret,
                delegatee_sub=label,
                delegatee_public_key_hex=ed25519.public_key(_secret(label)).hex(),
                requested_capabilities={
                    "database_read": {
                        "allowed": True,
                        "constraints": {"allowed_tables": ["customers"]},
                    }
                },
                time_iso=NOW,
            )
            hops.append(child)
            prev_secret = _secret(label)
            prev = child
        return issuer, hops

    def test_valid_chain(self):
        issuer, hops = self._chain(2)
        v = verify_passport_chain(
            hops, root_signer_key_hex=issuer.public_key_hex, time_iso=NOW
        )
        self.assertTrue(v.allowed, v.reason)
        self.assertEqual(v.depth, 2)

    def test_chain_discontinuity(self):
        issuer, hops = self._chain(2)
        other = _mint(_issuer(), sub="stranger",
                      public_key_hex=ed25519.public_key(_secret("stranger")).hex())
        broken = hops[:1] + [other]
        v = verify_passport_chain(
            broken, root_signer_key_hex=issuer.public_key_hex, time_iso=NOW
        )
        self.assertFalse(v.allowed)
        self.assertIn(v.failed_rule, ("chain_discontinuity", "signature_invalid", "depth_skew"))

    def test_depth_exceeded(self):
        issuer, hops = self._chain(5)
        v = verify_passport_chain(
            hops, root_signer_key_hex=issuer.public_key_hex, time_iso=NOW, max_depth=4
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "depth_exceeded")

    def test_malformed_max_depth(self):
        issuer, hops = self._chain(1)
        v = verify_passport_chain(
            hops, root_signer_key_hex=issuer.public_key_hex, time_iso=NOW, max_depth=0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "max_depth_malformed")

    def test_revoked_parent_kills_subtree(self):
        issuer, hops = self._chain(2)
        rl = RevocationList()
        rl.revoke(hops[0].jti, reason="root key rotation")
        v = verify_passport_chain(
            hops,
            root_signer_key_hex=issuer.public_key_hex,
            time_iso=NOW,
            revocation=rl,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "passport_revoked")

    def test_revoked_middle_kills_below(self):
        issuer, hops = self._chain(2)
        rl = RevocationList()
        rl.revoke(hops[1].jti, reason="delegatee compromised")
        v = verify_passport_chain(
            hops,
            root_signer_key_hex=issuer.public_key_hex,
            time_iso=NOW,
            revocation=rl,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.failed_rule, "passport_revoked")

    def test_tampered_child_caps_caught_by_invariant(self):
        # A child that widens its own caps after mint: the signature check
        # fires first (fail-closed either way).
        issuer, hops = self._chain(1)
        root, child = hops
        widened_caps = {
            "database_read": {
                "allowed": True,
                "constraints": {"allowed_tables": ["customers", "payments"]},
            }
        }
        from dataclasses import replace as _replace
        tampered = _replace(child, capabilities=widened_caps)
        v = verify_passport_chain(
            [root, tampered],
            root_signer_key_hex=issuer.public_key_hex,
            time_iso=NOW,
        )
        self.assertFalse(v.allowed)

    def test_capabilities_within(self):
        parent = _caps()
        child = {
            "database_read": {
                "allowed": True,
                "constraints": {"allowed_tables": ["customers"]},
            }
        }
        ok, _ = capabilities_within(child, parent)
        self.assertTrue(ok)
        wider = {
            "database_read": {
                "allowed": True,
                "constraints": {"allowed_tables": ["customers", "secrets"]},
            }
        }
        ok, reason = capabilities_within(wider, parent)
        self.assertFalse(ok)
        self.assertIn("allowed_tables", reason)


class IdentityWiringTests(unittest.TestCase):
    def test_passport_for_identity(self):
        agent_issuer = AgentIdentityIssuer.generate()
        identity, agent_secret = agent_issuer.issue("worker-1")
        issuer = _issuer()
        p = passport_for_identity(identity, issuer, _caps(), time_iso=NOW)
        self.assertEqual(p.did, identity.did)
        self.assertEqual(p.public_key_hex, identity.public_key_hex)
        # The identity key holder can delegate from this passport.
        child = delegate_passport(
            p,
            agent_secret,
            delegatee_sub="sub-1",
            delegatee_public_key_hex=ed25519.public_key(_secret("sub-1")).hex(),
            delegatee_did=did_of(ed25519.public_key(_secret("sub-1"))),
            requested_capabilities={
                "files_read": {"allowed": True, "constraints": {"max_rows": 10}}
            },
            time_iso=NOW,
        )
        v = verify_passport_chain(
            [p, child], root_signer_key_hex=issuer.public_key_hex, time_iso=NOW
        )
        self.assertTrue(v.allowed, v.reason)

    def test_passport_for_identity_rejects_junk(self):
        with self.assertRaises(PassportError):
            passport_for_identity(object(), _issuer(), _caps(), time_iso=NOW)


class AuditTests(unittest.TestCase):
    def test_audit_chain_round_trip(self):
        issuer = _issuer()
        p = _mint(issuer)
        child = delegate_passport(
            p,
            _secret("worker-1"),
            delegatee_sub="sub-1",
            delegatee_public_key_hex=ed25519.public_key(_secret("sub-1")).hex(),
            requested_capabilities={
                "files_read": {"allowed": True, "constraints": {"max_rows": 10}}
            },
            time_iso=NOW,
        )
        v = verify_passport_chain(
            [p, child], root_signer_key_hex=issuer.public_key_hex, time_iso=NOW
        )
        events = passport_audit_events(passport=p, chain=[p, child], verdict=v)
        kinds = [e["event"] for e in events]
        self.assertEqual(
            kinds, ["passport.issued", "passport.delegated", "passport.verified"]
        )
        lines = chain_records(events, component="northstar-agent-runtime")
        import json as _json

        text = "\n".join(
            _json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for r in lines
        )
        result = verify_lines(text.splitlines())
        self.assertTrue(result.ok, result)
        delegated = events[1]
        self.assertEqual(delegated["parent_jti"], p.jti)
        self.assertEqual(delegated["jti"], child.jti)

    def test_revocation_audit_event(self):
        events = passport_audit_events(revoked_jti="pp-deadbeef", note="compromise")
        self.assertEqual(events[0]["event"], "passport.revoked")
        self.assertEqual(events[0]["jti"], "pp-deadbeef")


if __name__ == "__main__":
    unittest.main()
