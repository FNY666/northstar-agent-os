"""Tests for portable, externally pinnable checkpoint-chain witnesses."""
from __future__ import annotations

import json
import unittest

from checkpoint_chain_witness import (
    CheckpointChainWitness,
    WitnessError,
    WitnessVerdict,
    make_witness,
    verify_witness,
)
from evidence_bundle import build_bundle
from evidence_chain import EvidenceChain


def bundle(number):
    return build_bundle([{
        "schema_version": "route.v2",
        "sequence": number,
        "event_id": "e%d" % number,
        "route_id": "r1",
        "status": "succeeded",
        "target_agent_id": "codex",
        "provider": "openai",
        "decision_fingerprint": "sha256:" + "b" * 64,
        "payload_digest": "sha256:" + str(number).zfill(64),
    }])


def chain(count=3):
    result = EvidenceChain()
    for number in range(1, count + 1):
        result.append(bundle(number))
    return result


class WitnessTests(unittest.TestCase):
    def test_complete_chain_witness_is_deterministic(self):
        first = make_witness(chain())
        second = make_witness(chain())
        self.assertEqual(first, second)
        self.assertEqual(first.checkpoint_count, 3)
        self.assertEqual(first.head_root, first.checkpoints[-1]["current_root"])
        self.assertTrue(first.chain_digest.startswith("sha256:"))

    def test_wire_form_round_trips_strictly(self):
        witness = make_witness(chain())
        restored = CheckpointChainWitness.from_dict(
            json.loads(json.dumps(witness.to_dict(), sort_keys=True))
        )
        self.assertEqual(restored, witness)
        with self.assertRaises(WitnessError):
            CheckpointChainWitness.from_dict({**witness.to_dict(), "extra": True})
        with self.assertRaises(WitnessError):
            CheckpointChainWitness.from_dict({})

    def test_empty_chain_is_refused(self):
        with self.assertRaises(WitnessError):
            make_witness(EvidenceChain())

    def test_external_pins_produce_verified(self):
        witness = make_witness(chain())
        verdict = verify_witness(
            witness,
            expected_head_root=witness.head_root,
            expected_chain_digest=witness.chain_digest,
        )
        self.assertIsInstance(verdict, WitnessVerdict)
        self.assertEqual(verdict.state, "verified")
        self.assertEqual(verdict.checkpoint_count, 3)
        self.assertEqual(verdict.head_root, witness.head_root)
        self.assertEqual(verdict.unverified, ())

    def test_missing_pins_are_explicit(self):
        witness = make_witness(chain())
        verdict = verify_witness(witness)
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("head_root_unpinned", verdict.unverified)
        self.assertIn("chain_digest_unpinned", verdict.unverified)

    def test_each_missing_pin_prevents_verified(self):
        witness = make_witness(chain())
        head_only = verify_witness(witness, expected_head_root=witness.head_root)
        digest_only = verify_witness(witness, expected_chain_digest=witness.chain_digest)
        self.assertEqual(head_only.state, "verified-unpinned")
        self.assertEqual(digest_only.state, "verified-unpinned")
        self.assertEqual(head_only.unverified, ("chain_digest_unpinned",))
        self.assertEqual(digest_only.unverified, ("head_root_unpinned",))

    def test_wrong_external_pins_are_rejected(self):
        witness = make_witness(chain())
        with self.assertRaises(WitnessError):
            verify_witness(witness, expected_head_root="sha256:" + "f" * 64)
        with self.assertRaises(WitnessError):
            verify_witness(witness, expected_chain_digest="sha256:" + "e" * 64)

    def test_reordered_checkpoint_is_rejected(self):
        witness = make_witness(chain())
        checkpoints = list(witness.checkpoints)
        checkpoints[0], checkpoints[1] = checkpoints[1], checkpoints[0]
        forged = CheckpointChainWitness(
            witness.schema_version,
            tuple(checkpoints),
            witness.checkpoint_count,
            witness.head_root,
            witness.chain_digest,
        )
        with self.assertRaises(WitnessError):
            verify_witness(forged)

    def test_checkpoint_tampering_is_rejected(self):
        witness = make_witness(chain())
        checkpoints = list(witness.checkpoints)
        checkpoints[1] = {**checkpoints[1], "evidence_count": 99}
        forged = CheckpointChainWitness(
            witness.schema_version, tuple(checkpoints), witness.checkpoint_count,
            witness.head_root, witness.chain_digest,
        )
        with self.assertRaises(WitnessError):
            verify_witness(forged)

    def test_truncation_with_old_digest_is_rejected(self):
        witness = make_witness(chain())
        forged = CheckpointChainWitness(
            witness.schema_version, witness.checkpoints[:-1],
            witness.checkpoint_count - 1,
            witness.checkpoints[-2]["current_root"],
            witness.chain_digest,
        )
        with self.assertRaises(WitnessError):
            verify_witness(forged)

    def test_recomputed_shorter_prefix_needs_external_pin_to_detect_rollback(self):
        full = make_witness(chain(3))
        prefix = make_witness(chain(2))
        unpinned = verify_witness(prefix)
        self.assertEqual(unpinned.state, "verified-unpinned")
        with self.assertRaises(WitnessError):
            verify_witness(
                prefix,
                expected_head_root=full.head_root,
                expected_chain_digest=full.chain_digest,
            )

    def test_historical_prefix_scope_is_explicit(self):
        prefix = make_witness(chain(2))
        verdict = verify_witness(
            prefix,
            expected_head_root=prefix.head_root,
            expected_chain_digest=prefix.chain_digest,
        )
        self.assertEqual(verdict.checkpoint_count, 2)
        self.assertEqual(verdict.head_root, prefix.head_root)

    def test_witness_has_no_raw_events_or_secrets(self):
        witness = make_witness(chain())
        encoded = json.dumps(witness.to_dict(), sort_keys=True)
        for forbidden in ("prompt", "secret", "raw_output", "event_id"):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
