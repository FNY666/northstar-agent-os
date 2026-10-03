"""m-of-n multisig approval: threshold enforcement, forgery detection, engine upgrade."""
from __future__ import annotations

import unittest

import support  # noqa: F401

from multisig import (
    MultisigGate,
    MultisigPolicy,
    MultisigSignature,
    derive_test_keypair,
    multisig_message,
    sign_call,
)
from permissions import (
    PermissionConfig,
    PermissionEngine,
    PermissionRequestContext,
    digest_arguments,
)


def _fixture():
    policy = MultisigPolicy(approvers=("alice", "bob", "carol"), threshold=2)
    keypairs = {n: derive_test_keypair(n) for n in ("alice", "bob", "carol", "mallory")}
    pubkeys = {n: keypairs[n][1] for n in policy.approvers}
    return policy, keypairs, pubkeys


class PolicyValidationTest(unittest.TestCase):
    def test_threshold_zero_rejected(self):
        with self.assertRaises(ValueError):
            MultisigPolicy(approvers=("a", "b"), threshold=0)

    def test_threshold_above_n_rejected(self):
        with self.assertRaises(ValueError):
            MultisigPolicy(approvers=("a", "b"), threshold=3)

    def test_duplicate_approvers_rejected(self):
        with self.assertRaises(ValueError):
            MultisigPolicy(approvers=("a", "a"), threshold=1)

    def test_gate_needs_every_pubkey(self):
        policy, _, pubkeys = _fixture()
        bad = dict(pubkeys)
        del bad["carol"]
        with self.assertRaises(ValueError):
            MultisigGate(policy, bad)


class MessageBindingTest(unittest.TestCase):
    def test_message_binds_call_id_and_digest(self):
        m1 = multisig_message("call-1", "sha256:aaa")
        m2 = multisig_message("call-2", "sha256:aaa")
        m3 = multisig_message("call-1", "sha256:bbb")
        self.assertNotEqual(m1, m2)
        self.assertNotEqual(m1, m3)

    def test_test_keys_are_deterministic(self):
        self.assertEqual(derive_test_keypair("alice"), derive_test_keypair("alice"))
        self.assertNotEqual(derive_test_keypair("alice")[1], derive_test_keypair("bob")[1])


class GateCheckTest(unittest.TestCase):
    def setUp(self):
        self.policy, self.keypairs, self.pubkeys = _fixture()
        self.gate = MultisigGate(self.policy, self.pubkeys)
        self.call_id = "call-9"
        self.digest = digest_arguments({"path": "x"})

    def _sig(self, who, *, key=None, cid=None, dgst=None):
        return MultisigSignature(
            who,
            sign_call(
                key or self.keypairs[who][0],
                cid or self.call_id,
                dgst or self.digest,
            ),
        )

    def test_two_valid_allows(self):
        verdict = self.gate.check(
            self.call_id, self.digest, [self._sig("alice"), self._sig("bob")]
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.valid_approvers, ("alice", "bob"))

    def test_single_signature_blocked(self):
        verdict = self.gate.check(self.call_id, self.digest, [self._sig("alice")])
        self.assertFalse(verdict.allowed)
        self.assertIn("not met", verdict.reason)

    def test_forged_signature_detected_and_named(self):
        forged = self._sig("bob", key=self.keypairs["mallory"][0])
        verdict = self.gate.check(
            self.call_id, self.digest, [self._sig("alice"), forged]
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(len(verdict.invalid), 1)
        approver_id, reason = verdict.invalid[0]
        self.assertEqual(approver_id, "bob")
        self.assertIn("does not verify", reason)

    def test_replay_across_arguments_blocked(self):
        other = digest_arguments({"path": "y"})
        verdict = self.gate.check(
            self.call_id,
            self.digest,
            [self._sig("alice", dgst=other), self._sig("bob")],
        )
        self.assertFalse(verdict.allowed)

    def test_replay_across_call_ids_blocked(self):
        verdict = self.gate.check(
            self.call_id,
            self.digest,
            [self._sig("alice", cid="other-call"), self._sig("bob")],
        )
        self.assertFalse(verdict.allowed)

    def test_duplicate_counts_once(self):
        verdict = self.gate.check(
            self.call_id, self.digest, [self._sig("alice"), self._sig("alice")]
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(any("duplicate" in r for _, r in verdict.invalid))

    def test_unknown_approver_rejected(self):
        mallory_sig = self._sig("mallory")
        verdict = self.gate.check(
            self.call_id, self.digest, [self._sig("alice"), mallory_sig]
        )
        self.assertFalse(verdict.allowed)
        self.assertTrue(any("unknown approver" in r for _, r in verdict.invalid))

    def test_malformed_signature_rejected(self):
        verdict = self.gate.check(
            self.call_id,
            self.digest,
            [self._sig("alice"), MultisigSignature("bob", "zzzz")],
        )
        self.assertFalse(verdict.allowed)

    def test_empty_signatures_deny(self):
        verdict = self.gate.check(self.call_id, self.digest, [])
        self.assertFalse(verdict.allowed)


class EngineIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.policy, self.keypairs, self.pubkeys = _fixture()
        self.call_id = "call-7"
        self.args = {"path": "prod.db"}
        self.digest = digest_arguments(self.args)

    def _engine(self, callback):
        return PermissionEngine(
            PermissionConfig(multisig=self.policy, can_use_tool=callback),
            multisig_pubkeys=self.pubkeys,
        )

    def _sig(self, who):
        return MultisigSignature(
            who, sign_call(self.keypairs[who][0], self.call_id, self.digest)
        )

    def test_allow_upgrades_callback_yes(self):
        ctx = PermissionRequestContext(
            call_id=self.call_id,
            arguments_digest=self.digest,
            multisig_signatures=(self._sig("alice"), self._sig("carol")),
        )
        decision = self._engine(lambda *a: True).evaluate(
            "Write", kind="edit", payload=dict(self.args), context=ctx
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "multisig")
        self.assertEqual(
            decision.as_dict()["details"]["valid_approvers"], ["alice", "carol"]
        )
        self.assertEqual(len(decision.as_dict()["details"]["signatures"]), 2)

    def test_deny_without_signatures(self):
        ctx = PermissionRequestContext(
            call_id=self.call_id, arguments_digest=self.digest
        )
        decision = self._engine(lambda *a: True).evaluate(
            "Write", kind="edit", payload=dict(self.args), context=ctx
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "multisig")

    def test_callback_refuse_still_denies(self):
        ctx = PermissionRequestContext(
            call_id=self.call_id,
            arguments_digest=self.digest,
            multisig_signatures=(self._sig("alice"), self._sig("bob")),
        )
        decision = self._engine(lambda *a: False).evaluate(
            "Write", kind="edit", payload=dict(self.args), context=ctx
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "host_callback")

    def test_policy_without_pubkeys_fails_loud(self):
        with self.assertRaises(ValueError):
            PermissionEngine(PermissionConfig(multisig=self.policy, can_use_tool=lambda *a: True))

    def test_no_policy_behaves_as_before(self):
        engine = PermissionEngine(PermissionConfig(can_use_tool=lambda *a: True))
        decision = engine.evaluate("Write", kind="edit", payload=dict(self.args))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "host_callback")


if __name__ == "__main__":
    unittest.main()
