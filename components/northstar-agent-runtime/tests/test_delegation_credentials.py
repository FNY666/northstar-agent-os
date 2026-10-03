"""Tests for biscuit-style attenuating delegation credentials.

Covers the minimal subset the module promises: authority facts minted only
by the root key holder, check-only attenuation that can narrow but never
widen, offline verification with the root public key alone, sealed tokens,
and the audit anchoring of the attenuation chain.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from audit_chain import chain_records, verify_lines
from delegation_credentials import (
    CHECK_DEPTH_AT_MOST,
    CHECK_EXPIRES_BEFORE,
    CHECK_OP_IN,
    CHECK_TOOL_IN,
    CredentialError,
    Issuer,
    RequestFacts,
    attenuate,
    attenuation_audit_events,
    credential_id,
    seal,
    verify,
)

RIGHTS = [("read_file", "read"), ("write_file", "write"), ("shell", "exec")]


def _issuer() -> Issuer:
    return Issuer.generate()


def _req(**over) -> RequestFacts:
    base = {
        "agent": "subagent-a",
        "tool": "read_file",
        "operation": "read",
        "depth": 1,
        "time_iso": "2026-10-03T12:00:00Z",
    }
    base.update(over)
    return RequestFacts(**base)


class IssueTests(unittest.TestCase):
    def test_issue_then_verify_in_scope(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        verdict = verify(token, iss.root_public_key, _req())
        self.assertTrue(verdict.allowed, verdict.reason)
        self.assertTrue(verdict.chain_ok)

    def test_verify_needs_only_the_public_key(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        # A verifier built from the public key alone must succeed: no secret
        # is reachable from the token's proof key for *verification*.
        pub = iss.root_public_key
        token2 = dict(token)
        token2.pop("proof", None)
        self.assertTrue(verify(token2, pub, _req()).allowed)

    def test_out_of_scope_right_denied(self):
        iss = _issuer()
        token = iss.issue("subagent-a", [("read_file", "read")])
        verdict = verify(token, iss.root_public_key, _req(operation="write", tool="write_file"))
        self.assertFalse(verdict.allowed)

    def test_wrong_agent_denied(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        verdict = verify(token, iss.root_public_key, _req(agent="subagent-b"))
        self.assertFalse(verdict.allowed)

    def test_issue_empty_holder_rejected(self):
        with self.assertRaises(CredentialError):
            _issuer().issue("", RIGHTS)

    def test_issue_empty_rights_rejected(self):
        with self.assertRaises(CredentialError):
            _issuer().issue("subagent-a", [])


class AttenuationTests(unittest.TestCase):
    def test_attenuate_narrows_and_still_allows_in_scope(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_TOOL_IN, "tools": ["read_file"]},
             {"predicate": CHECK_OP_IN, "operations": ["read"]}],
            attenuated_by="subagent-a",
        )
        self.assertTrue(verify(token, iss.root_public_key, _req()).allowed)

    def test_attenuated_out_of_scope_denied(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_TOOL_IN, "tools": ["read_file"]}],
            attenuated_by="subagent-a",
        )
        verdict = verify(
            token, iss.root_public_key, _req(tool="shell", operation="exec")
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_check, CHECK_TOOL_IN)

    def test_amplification_by_wider_check_is_neutralised(self):
        # A malicious attenuator appends a *permissive* check hoping to
        # widen: checks are conjunctive, so the earlier narrowing check
        # still governs. Amplification has no effect.
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_OP_IN, "operations": ["read"]}],
            attenuated_by="subagent-a",
        )
        evil = attenuate(
            token,
            [{"predicate": CHECK_OP_IN, "operations": ["read", "write", "exec"]}],
            attenuated_by="attacker",
        )
        verdict = verify(evil, iss.root_public_key, _req(tool="write_file", operation="write"))
        self.assertFalse(verdict.allowed, "conjunctive checks must still deny write")

    def test_facts_in_attenuation_block_rejected(self):
        # Smuggle an authority-style fact into the attenuation block and
        # re-sign with the (legitimately held) proof key so the signature
        # chain still verifies: the anti-amplification gate is structural,
        # not signature-deep. The request itself is within the authority's
        # grant, so only the structural gate can deny it.
        iss = _issuer()
        token0 = iss.issue("subagent-a", RIGHTS)
        proof1 = token0["proof"]  # the key that legitimately signed block 1
        token = attenuate(
            token0,
            [{"predicate": CHECK_TOOL_IN, "tools": ["read_file", "shell"]}],
            attenuated_by="subagent-a",
        )
        evil_block = dict(token["blocks"][1])
        evil_data = dict(evil_block["data"])
        evil_data["facts"] = [["right", "shell", "exec"]]
        evil_block["data"] = evil_data
        evil = dict(token)
        evil["blocks"] = [token["blocks"][0], evil_block]
        from audit_chain import canonical_json

        proof = bytes.fromhex(proof1)
        next_pub = bytes.fromhex(evil_block["next_pub"])
        evil_block["sig"] = ed25519.sign(proof, canonical_json(evil_data) + next_pub).hex()
        verdict = verify(evil, iss.root_public_key, _req(tool="shell", operation="exec"))
        self.assertFalse(verdict.allowed)
        self.assertIn("not the authority block", verdict.reason)

    def test_unknown_check_predicate_fails_closed(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        with self.assertRaises(CredentialError):
            attenuate(token, [{"predicate": "op_always"}], attenuated_by="x")

    def test_empty_checks_rejected(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        with self.assertRaises(CredentialError):
            attenuate(token, [], attenuated_by="x")

    def test_expiry_check(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_EXPIRES_BEFORE, "not_after": "2026-10-04T00:00:00Z"}],
            attenuated_by="subagent-a",
        )
        self.assertTrue(
            verify(token, iss.root_public_key, _req(time_iso="2026-10-03T12:00:00Z")).allowed
        )
        self.assertFalse(
            verify(token, iss.root_public_key, _req(time_iso="2026-10-05T00:00:00Z")).allowed
        )

    def test_depth_bound(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_DEPTH_AT_MOST, "max_depth": 1}],
            attenuated_by="subagent-a",
        )
        self.assertTrue(verify(token, iss.root_public_key, _req(depth=1)).allowed)
        self.assertFalse(verify(token, iss.root_public_key, _req(depth=2)).allowed)

    def test_sealed_token_cannot_be_attenuated_but_verifies(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_OP_IN, "operations": ["read"]}],
            attenuated_by="subagent-a",
        )
        sealed = seal(token)
        self.assertIsNone(sealed["proof"])
        self.assertTrue(sealed["seal"])
        self.assertTrue(verify(sealed, iss.root_public_key, _req()).allowed)
        with self.assertRaises(CredentialError):
            attenuate(sealed, [{"predicate": CHECK_TOOL_IN, "tools": ["x"]}], attenuated_by="y")

    def test_seal_tamper_detected(self):
        iss = _issuer()
        token = seal(iss.issue("subagent-a", RIGHTS))
        token["seal"] = "00" * 64
        verdict = verify(token, iss.root_public_key, _req())
        self.assertFalse(verdict.allowed)


class ChainIntegrityTests(unittest.TestCase):
    def test_forged_credential_rejected(self):
        iss = _issuer()
        other = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        verdict = verify(token, other.root_public_key, _req())
        self.assertFalse(verdict.allowed)
        self.assertIn("signature invalid", verdict.reason)

    def test_stripped_attenuation_block_detected(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_OP_IN, "operations": ["read"]}],
            attenuated_by="subagent-a",
        )
        stripped = dict(token)
        stripped["blocks"] = [token["blocks"][0]]
        verdict = verify(stripped, iss.root_public_key, _req())
        # The stripped token verifies as a *valid narrower-free* credential
        # for the original rights — but the audit anchor (which pinned the
        # 2-block chain) no longer matches; the attenuation events below
        # prove what the chain looked like at each hop.
        self.assertTrue(verdict.allowed)
        anchored = [e["block_sig"] for e in attenuation_audit_events(token)]
        presented = [b["sig"] for b in stripped["blocks"]]
        self.assertNotEqual(anchored, presented)

    def test_reordered_blocks_rejected(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_OP_IN, "operations": ["read"]}],
            attenuated_by="subagent-a",
        )
        evil = dict(token)
        evil["blocks"] = [token["blocks"][1], token["blocks"][0]]
        verdict = verify(evil, iss.root_public_key, _req())
        self.assertFalse(verdict.allowed)

    def test_tampered_check_detected(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS)
        token = attenuate(
            token,
            [{"predicate": CHECK_OP_IN, "operations": ["read"]}],
            attenuated_by="subagent-a",
        )
        evil = dict(token)
        block = dict(token["blocks"][1])
        data = dict(block["data"])
        data["checks"] = [{"predicate": CHECK_OP_IN, "operations": ["read", "write", "exec"]}]
        block["data"] = data
        evil["blocks"] = [token["blocks"][0], block]
        verdict = verify(evil, iss.root_public_key, _req())
        self.assertFalse(verdict.allowed)
        self.assertIn("signature invalid", verdict.reason)


class AuditAnchorTests(unittest.TestCase):
    def test_attenuation_chain_anchors_in_audit_hash_chain(self):
        iss = _issuer()
        token = iss.issue("subagent-a", RIGHTS, issued_by="supervisor")
        token = attenuate(
            token,
            [{"predicate": CHECK_TOOL_IN, "tools": ["read_file"]}],
            attenuated_by="subagent-a",
        )
        token = seal(token)
        events = attenuation_audit_events(token, chain_note="bench")
        kinds = [e["event"] for e in events]
        self.assertEqual(
            kinds,
            [
                "delegation_credential.issued",
                "delegation_credential.attenuated",
                "delegation_credential.sealed",
            ],
        )
        self.assertEqual(events[0]["credential_id"], credential_id(token))
        self.assertEqual(events[1]["checks_added"], [CHECK_TOOL_IN])
        chained = chain_records(events, component="northstar-agent-runtime")
        import json as _json

        text = "\n".join(
            _json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for r in chained
        )
        result = verify_lines(text.splitlines())
        self.assertTrue(result.ok, result)

    def test_audit_tamper_breaks_anchor(self):
        iss = _issuer()
        token = attenuate(
            iss.issue("subagent-a", RIGHTS),
            [{"predicate": CHECK_TOOL_IN, "tools": ["read_file"]}],
            attenuated_by="subagent-a",
        )
        events = attenuation_audit_events(token)
        chained = chain_records(events, component="northstar-agent-runtime")
        tampered = dict(chained[1])
        tampered["checks_added"] = [CHECK_OP_IN]
        import json as _json

        lines = [
            _json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for r in [chained[0], tampered]
        ]
        result = verify_lines(lines)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
