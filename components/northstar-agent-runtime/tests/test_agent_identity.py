"""Tests for DID-based agent identity, delegation chains with depth limits,
and permission-combination prohibition.

Covers: identity issuance (DID binds key, self-resolving), revocation,
delegation chains (continuity, signature per hop, attenuation, depth
ceiling, expiry), combination prohibition (each permission alone is fine,
the combination is denied; malformed rules fail closed), and the audit
anchoring of identity events.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_identity import (
    DEFAULT_MAX_DEPTH,
    DID_METHOD,
    AgentIdentity,
    CombinationRule,
    DelegationRecord,
    IdentityError,
    IdentityIssuer,
    check_combination_prohibition,
    combination_rule,
    did_of,
    evaluate_request,
    identity_audit_events,
    parse_did,
    verify_delegation_chain,
    verify_identity,
)
from audit_chain import chain_records, verify_lines

NOW = "2026-10-04T01:00:00Z"


def _issuer() -> IdentityIssuer:
    return IdentityIssuer.generate()


def _keypair() -> tuple[bytes, bytes]:
    import ed25519

    secret = os.urandom(32)
    return secret, ed25519.public_key(secret)


class DidTests(unittest.TestCase):
    def test_did_format(self):
        _, pub = _keypair()
        did = did_of(pub)
        self.assertTrue(did.startswith(f"did:{DID_METHOD}:"))
        self.assertEqual(len(did), len("did:northstar:") + 64)

    def test_did_round_trip(self):
        _, pub = _keypair()
        self.assertEqual(parse_did(did_of(pub)), pub)

    def test_parse_rejects_non_did(self):
        self.assertIsNone(parse_did("not-a-did"))
        self.assertIsNone(parse_did("did:other:abcd"))
        self.assertIsNone(parse_did("did:northstar:xyz"))  # not hex
        self.assertIsNone(parse_did("did:northstar:" + "ab" * 16))  # short
        self.assertIsNone(parse_did(None))  # type: ignore[arg-type]
        self.assertIsNone(parse_did(123))  # type: ignore[arg-type]

    def test_did_rejects_bad_key_length(self):
        with self.assertRaises(IdentityError):
            did_of(b"short")


class IssueTests(unittest.TestCase):
    def test_issue_binds_did_to_key(self):
        iss = _issuer()
        identity, secret = iss.issue("worker-1", role="worker", issued_at=NOW)
        self.assertEqual(
            identity.did, did_of(bytes.fromhex(identity.public_key_hex))
        )
        self.assertEqual(identity.agent, "worker-1")
        self.assertEqual(identity.role, "worker")

    def test_issue_empty_agent_rejected(self):
        iss = _issuer()
        with self.assertRaises(IdentityError):
            iss.issue("   ")

    def test_verify_identity_ok(self):
        iss = _issuer()
        identity, _ = iss.issue("worker-1", issued_at=NOW)
        verdict = verify_identity(identity)
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_verify_identity_did_key_mismatch(self):
        iss = _issuer()
        identity, _ = iss.issue("worker-1", issued_at=NOW)
        _, other_pub = _keypair()
        tampered = AgentIdentity(
            did=did_of(other_pub),
            agent=identity.agent,
            role=identity.role,
            public_key_hex=identity.public_key_hex,
            issued_by=identity.issued_by,
            issued_at=identity.issued_at,
        )
        verdict = verify_identity(tampered)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "did_key_mismatch")

    def test_verify_identity_revoked(self):
        iss = _issuer()
        identity, _ = iss.issue("worker-1", issued_at=NOW)
        verdict = verify_identity(identity, revoked_dids=[identity.did])
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "revoked")

    def test_verify_identity_revoked_flag(self):
        iss = _issuer()
        identity, _ = iss.issue("worker-1", issued_at=NOW)
        revoked = AgentIdentity(
            did=identity.did,
            agent=identity.agent,
            role=identity.role,
            public_key_hex=identity.public_key_hex,
            issued_by=identity.issued_by,
            issued_at=identity.issued_at,
            revoked=True,
        )
        verdict = verify_identity(revoked)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "revoked")


def _chain_fixture(
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> tuple[IdentityIssuer, AgentIdentity, list[DelegationRecord], list[bytes]]:
    """Root -> worker -> subagent, depth 1 and 2, secrets returned."""
    iss = _issuer()
    worker, worker_secret = iss.issue("worker-1", issued_at=NOW)
    sub, sub_secret = iss.issue("subagent-a", issued_at=NOW)
    root_perms = ("read:files", "write:files", "net:egress")
    hop1 = iss.delegate(
        iss._root_secret,  # root delegates with its own key
        iss.root_did,
        worker.did,
        ("read:files", "write:files"),
        depth=1,
        purpose="worker duties",
    )
    hop2 = iss.delegate(
        worker_secret,
        worker.did,
        sub.did,
        ("read:files",),
        depth=2,
        purpose="review subtask",
    )
    return iss, sub, [hop1, hop2], [worker_secret, sub_secret]


class DelegationChainTests(unittest.TestCase):
    def test_valid_chain(self):
        iss, sub, chain, _ = _chain_fixture()
        verdict = verify_delegation_chain(
            chain, iss.root_did, ("read:files", "write:files", "net:egress"), time_iso=NOW
        )
        self.assertTrue(verdict.allowed, verdict.reason)
        self.assertEqual(verdict.depth, 2)

    def test_empty_chain_rejected(self):
        iss = _issuer()
        verdict = verify_delegation_chain([], iss.root_did, ("read:files",), time_iso=NOW)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "empty_chain")

    def test_chain_discontinuity_rejected(self):
        iss, sub, chain, _ = _chain_fixture()
        other, _ = iss.issue("intruder", issued_at=NOW)
        broken = list(chain)
        broken[1] = DelegationRecord(
            delegator_did=other.did,  # not the previous delegatee
            delegatee_did=broken[1].delegatee_did,
            permissions=broken[1].permissions,
            depth=broken[1].depth,
            signature=broken[1].signature,
        )
        verdict = verify_delegation_chain(
            broken, iss.root_did, ("read:files", "write:files", "net:egress"), time_iso=NOW
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "chain_discontinuity")

    def test_tampered_signature_rejected(self):
        iss, sub, chain, _ = _chain_fixture()
        broken = list(chain)
        first = broken[0]
        broken[0] = DelegationRecord(
            delegator_did=first.delegator_did,
            delegatee_did=first.delegatee_did,
            permissions=first.permissions,
            depth=first.depth,
            signature="00" * 64,  # forged
        )
        verdict = verify_delegation_chain(
            broken, iss.root_did, ("read:files", "write:files", "net:egress"), time_iso=NOW
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "signature_invalid")

    def test_amplification_rejected(self):
        """A delegatee can never hold more than its delegator."""
        iss = _issuer()
        worker, worker_secret = iss.issue("worker-1", issued_at=NOW)
        sub, _ = iss.issue("subagent-a", issued_at=NOW)
        hop1 = iss.delegate(
            iss._root_secret, iss.root_did, worker.did, ("read:files",), depth=1
        )
        # worker tries to grant net:egress it never held
        hop2 = iss.delegate(
            worker_secret, worker.did, sub.did, ("read:files", "net:egress"), depth=2
        )
        verdict = verify_delegation_chain(
            [hop1, hop2], iss.root_did, ("read:files",), time_iso=NOW
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "attenuation_violated")

    def test_depth_ceiling_enforced(self):
        """A chain deeper than max_depth fails closed at the exceeding hop."""
        iss = _issuer()
        root_perms = ("read:files",)
        prev_did = iss.root_did
        prev_secret = iss._root_secret
        chain: list[DelegationRecord] = []
        for depth in range(1, 6):
            nxt, nxt_secret = iss.issue(f"hop-{depth}", issued_at=NOW)
            hop = iss.delegate(
                prev_secret, prev_did, nxt.did, root_perms, depth=depth
            )
            chain.append(hop)
            prev_did, prev_secret = nxt.did, nxt_secret
        verdict = verify_delegation_chain(
            chain, iss.root_did, root_perms, max_depth=4, time_iso=NOW
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "depth_exceeded")
        self.assertEqual(verdict.depth, 5)

    def test_depth_ceiling_boundary(self):
        """Depth exactly at max_depth is allowed."""
        iss = _issuer()
        root_perms = ("read:files",)
        prev_did = iss.root_did
        prev_secret = iss._root_secret
        chain: list[DelegationRecord] = []
        for depth in range(1, 5):
            nxt, nxt_secret = iss.issue(f"hop-{depth}", issued_at=NOW)
            chain.append(iss.delegate(prev_secret, prev_did, nxt.did, root_perms, depth=depth))
            prev_did, prev_secret = nxt.did, nxt_secret
        verdict = verify_delegation_chain(
            chain, iss.root_did, root_perms, max_depth=4, time_iso=NOW
        )
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_malformed_max_depth_fails_closed(self):
        iss, sub, chain, _ = _chain_fixture()
        for bad in (0, -1, "4", None, True):
            verdict = verify_delegation_chain(
                chain, iss.root_did, ("read:files",), max_depth=bad, time_iso=NOW  # type: ignore[arg-type]
            )
            self.assertFalse(verdict.allowed, f"max_depth={bad!r} must fail closed")
            self.assertEqual(verdict.failed_rule, "max_depth_malformed")

    def test_expired_delegation_rejected(self):
        iss = _issuer()
        worker, _ = iss.issue("worker-1", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret,
            iss.root_did,
            worker.did,
            ("read:files",),
            depth=1,
            expires_at="2026-01-01T00:00:00Z",
        )
        verdict = verify_delegation_chain(
            [hop], iss.root_did, ("read:files",), time_iso=NOW
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "delegation_expired")

    def test_expiry_without_reference_time_fails_closed(self):
        iss = _issuer()
        worker, _ = iss.issue("worker-1", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret,
            iss.root_did,
            worker.did,
            ("read:files",),
            depth=1,
            expires_at="2027-01-01T00:00:00Z",
        )
        verdict = verify_delegation_chain([hop], iss.root_did, ("read:files",))
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "expiry_uncheckable")

    def test_depth_skew_rejected(self):
        iss = _issuer()
        worker, _ = iss.issue("worker-1", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret, iss.root_did, worker.did, ("read:files",), depth=3
        )
        verdict = verify_delegation_chain(
            [hop], iss.root_did, ("read:files",), time_iso=NOW
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "depth_skew")


class CombinationProhibitionTests(unittest.TestCase):
    def test_single_permissions_allowed(self):
        """Each permission alone is innocent: no rule fires."""
        rule = combination_rule(
            "secret-exfiltration", ("read:secrets", "net:egress"), why="test"
        )
        ok, fired = check_combination_prohibition(("read:secrets",), [rule])
        self.assertTrue(ok)
        self.assertIsNone(fired)
        ok, fired = check_combination_prohibition(("net:egress",), [rule])
        self.assertTrue(ok)

    def test_combination_denied(self):
        """The combination together is denied even though each alone is allowed."""
        rule = combination_rule(
            "secret-exfiltration", ("read:secrets", "net:egress"), why="test"
        )
        ok, fired = check_combination_prohibition(
            ("read:secrets", "net:egress"), [rule]
        )
        self.assertFalse(ok)
        self.assertIsNotNone(fired)
        assert fired is not None
        self.assertEqual(fired.name, "secret-exfiltration")

    def test_combination_superset_denied(self):
        """A superset of the forbidden combination still fires."""
        rule = combination_rule("priv-esc", ("admin:users", "billing:refund"))
        ok, fired = check_combination_prohibition(
            ("read:files", "admin:users", "billing:refund"), [rule]
        )
        self.assertFalse(ok)
        self.assertEqual(fired.name, "priv-esc")  # type: ignore[union-attr]

    def test_first_firing_rule_reported(self):
        r1 = combination_rule("a", ("p1", "p2"))
        r2 = combination_rule("b", ("p2", "p3"))
        ok, fired = check_combination_prohibition(("p1", "p2", "p3"), [r1, r2])
        self.assertFalse(ok)
        self.assertEqual(fired.name, "a")  # type: ignore[union-attr]

    def test_no_rules_allows(self):
        ok, fired = check_combination_prohibition(("anything", "at-all"), [])
        self.assertTrue(ok)
        self.assertIsNone(fired)

    def test_malformed_rule_spec_rejected(self):
        with self.assertRaises(IdentityError):
            combination_rule("", ("a", "b"))
        with self.assertRaises(IdentityError):
            combination_rule("solo", ("a",))  # single permission is a gate denial
        with self.assertRaises(IdentityError):
            combination_rule("dupes", ("a", "a", " "))
        with self.assertRaises(IdentityError):
            combination_rule("empty", ())

    def test_malformed_rule_object_fails_closed(self):
        """A non-CombinationRule in the policy list denies, never skips."""
        ok, fired = check_combination_prohibition(("a", "b"), ["not-a-rule"])  # type: ignore[list-item]
        self.assertFalse(ok)
        self.assertIsNone(fired)


class EvaluateRequestTests(unittest.TestCase):
    def _setup(self):
        iss = _issuer()
        worker, worker_secret = iss.issue("worker-1", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret,
            iss.root_did,
            worker.did,
            ("read:secrets", "net:egress"),
            depth=1,
        )
        return iss, worker, [hop]

    def test_full_gate_allows_clean_request(self):
        iss, worker, chain = self._setup()
        verdict = evaluate_request(
            identity=worker,
            chain=chain,
            root_did=iss.root_did,
            root_permissions=("read:secrets", "net:egress", "read:files"),
            requested_permissions=("read:files",),
            combination_rules=[
                combination_rule("secret-exfiltration", ("read:secrets", "net:egress"))
            ],
            time_iso=NOW,
        )
        # effective set = chain grant {read:secrets, net:egress} + requested
        # {read:files} -> the combination IS present -> denied
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "combination_prohibited")

    def test_combination_denies_dangerous_pair(self):
        """The classic exfiltration shape: read secrets + network egress."""
        iss = _issuer()
        reader, reader_secret = iss.issue("reader", issued_at=NOW)
        netter, _ = iss.issue("netter", issued_at=NOW)
        hop_r = iss.delegate(
            iss._root_secret, iss.root_did, reader.did, ("read:secrets",), depth=1
        )
        # reader asks to also exercise net:egress this request
        verdict = evaluate_request(
            identity=reader,
            chain=[hop_r],
            root_did=iss.root_did,
            root_permissions=("read:secrets", "net:egress"),
            requested_permissions=("net:egress",),
            combination_rules=[
                combination_rule("secret-exfiltration", ("read:secrets", "net:egress"))
            ],
            time_iso=NOW,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "combination_prohibited")

    def test_innocent_pair_allowed(self):
        iss = _issuer()
        reader, _ = iss.issue("reader", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret, iss.root_did, reader.did, ("read:files",), depth=1
        )
        verdict = evaluate_request(
            identity=reader,
            chain=[hop],
            root_did=iss.root_did,
            root_permissions=("read:files", "read:docs"),
            requested_permissions=("read:docs",),
            combination_rules=[
                combination_rule("secret-exfiltration", ("read:secrets", "net:egress"))
            ],
            time_iso=NOW,
        )
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_chain_not_terminating_at_caller_rejected(self):
        iss = _issuer()
        worker, _ = iss.issue("worker-1", issued_at=NOW)
        other, _ = iss.issue("other", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret, iss.root_did, worker.did, ("read:files",), depth=1
        )
        verdict = evaluate_request(
            identity=other,  # different identity than the chain's delegatee
            chain=[hop],
            root_did=iss.root_did,
            root_permissions=("read:files",),
            requested_permissions=("read:files",),
            time_iso=NOW,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "chain_identity_mismatch")

    def test_revoked_identity_denied(self):
        iss, worker, chain = self._setup()
        verdict = evaluate_request(
            identity=worker,
            chain=chain,
            root_did=iss.root_did,
            root_permissions=("read:secrets", "net:egress"),
            requested_permissions=(),
            revoked_dids=[worker.did],
            time_iso=NOW,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "revoked")

    def test_deep_chain_denied_at_gate(self):
        iss = _issuer()
        root_perms = ("read:files",)
        prev_did, prev_secret = iss.root_did, iss._root_secret
        chain: list[DelegationRecord] = []
        for depth in range(1, 6):
            nxt, nxt_secret = iss.issue(f"hop-{depth}", issued_at=NOW)
            chain.append(
                iss.delegate(prev_secret, prev_did, nxt.did, root_perms, depth=depth)
            )
            prev_did, prev_secret = nxt.did, nxt_secret
        final_identity = AgentIdentity(
            did=prev_did,
            agent="hop-5",
            role="agent",
            public_key_hex=prev_did.split(":")[2],
            issued_by="supervisor",
            issued_at=NOW,
        )
        verdict = evaluate_request(
            identity=final_identity,
            chain=chain,
            root_did=iss.root_did,
            root_permissions=root_perms,
            requested_permissions=(),
            max_depth=4,
            time_iso=NOW,
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_rule, "depth_exceeded")


class AuditEventTests(unittest.TestCase):
    def test_events_anchor_in_hash_chain(self):
        iss = _issuer()
        identity, _ = iss.issue("worker-1", issued_at=NOW)
        worker2, _ = iss.issue("worker-2", issued_at=NOW)
        hop = iss.delegate(
            iss._root_secret, iss.root_did, worker2.did, ("read:files",), depth=1
        )
        verdict = verify_delegation_chain(
            [hop], iss.root_did, ("read:files",), time_iso=NOW
        )
        events = identity_audit_events(identity=identity, chain=[hop], verdict=verdict)
        kinds = [e["event"] for e in events]
        self.assertEqual(
            kinds,
            [
                "agent_identity.issued",
                "agent_identity.delegated",
                "agent_identity.verified",
            ],
        )
        lines = chain_records(events, component="northstar-agent-runtime")
        import json as _json

        text = "\n".join(
            _json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for r in lines
        )
        result = verify_lines(text.splitlines())
        self.assertTrue(result.ok, result)

    def test_denial_event_named(self):
        iss = _issuer()
        identity, _ = iss.issue("worker-1", issued_at=NOW)
        events = identity_audit_events(identity=identity, verdict=None)
        self.assertEqual(events[0]["event"], "agent_identity.issued")
        self.assertEqual(events[0]["did"], identity.did)


if __name__ == "__main__":
    unittest.main()
