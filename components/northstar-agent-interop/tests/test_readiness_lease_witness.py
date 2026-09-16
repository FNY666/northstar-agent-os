"""Tests for replayable readiness-lease registry observations."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from plan_evidence_decision import derive_plan_id
from evidence_readiness_lease import EvidenceReadinessLease, SCHEMA as LEASE_SCHEMA
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry
from readiness_lease_witness import (
    LeaseRegistryWitness,
    RegistryWitnessError,
    RegistryWitnessVerdict,
    make_registry_witness,
    verify_registry_witness,
)

D = lambda char: "sha256:" + char * 64


def lease(suffix="a", issued=1000, expires=1060):
    draft = EvidenceReadinessLease(
        LEASE_SCHEMA, derive_plan_id(D("b")), D(suffix), D("b"), D("c"),
        issued, expires, False, "",
    )
    return EvidenceReadinessLease(
        draft.schema_version, draft.plan_id, draft.decision_digest,
        draft.manifest_digest, draft.gate_digest, issued, expires, False,
        draft.computed_digest,
    )


class WitnessFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="lease-witness-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.registry = EvidenceReadinessLeaseRegistry(self.root)
        self.value = lease()
        self.registry.register(self.value)


class SnapshotTests(WitnessFixture):
    def test_active_snapshot_is_deterministic_and_pinned(self):
        first = make_registry_witness(self.registry, self.value.lease_digest, now=1010)
        second = make_registry_witness(self.registry, self.value.lease_digest, now=1010)
        self.assertEqual(first, second)
        self.assertEqual(first.observed_state, "active")
        self.assertEqual(first.record_sequence, 1)
        self.assertTrue(first.registry_head_digest.startswith("sha256:"))
        verdict = verify_registry_witness(
            first, self.registry, now=1010,
            expected_witness_digest=first.witness_digest,
        )
        self.assertIsInstance(verdict, RegistryWitnessVerdict)
        self.assertEqual(verdict.state, "current")
        self.assertFalse(verdict.execution_authorized)

    def test_expired_and_revoked_observations_are_captured(self):
        expired = make_registry_witness(self.registry, self.value.lease_digest, now=1061)
        self.assertEqual(expired.observed_state, "expired")
        self.assertEqual(verify_registry_witness(expired, self.registry, now=1061).state, "expired")
        self.registry.revoke(self.value.lease_digest)
        revoked = make_registry_witness(self.registry, self.value.lease_digest, now=1010)
        self.assertEqual(revoked.observed_state, "revoked")
        self.assertEqual(verify_registry_witness(revoked, self.registry, now=1010).state, "revoked" )

    def test_unknown_lease_is_captured_as_unknown(self):
        witness = make_registry_witness(self.registry, D("f"), now=1010)
        self.assertEqual(witness.observed_state, "unknown")
        self.assertEqual(verify_registry_witness(witness, self.registry, now=1010).state, "unknown")

    def test_wire_form_is_strict_and_contains_no_raw_fields(self):
        witness = make_registry_witness(self.registry, self.value.lease_digest, now=1010)
        self.assertEqual(LeaseRegistryWitness.from_dict(witness.to_dict()), witness)
        with self.assertRaises(RegistryWitnessError):
            LeaseRegistryWitness.from_dict({**witness.to_dict(), "extra": True})
        rendered = json.dumps(witness.to_dict(), sort_keys=True)
        for forbidden in ("prompt", "command", "event_id", "secret", "output"):
            self.assertNotIn(forbidden, rendered)


class DriftTests(WitnessFixture):
    def setUp(self):
        super().setUp()
        self.witness = make_registry_witness(self.registry, self.value.lease_digest, now=1010)

    def test_missing_external_witness_pin_is_explicit(self):
        verdict = verify_registry_witness(self.witness, self.registry, now=1010)
        self.assertEqual(verdict.state, "current-unpinned")
        self.assertIn("witness_digest_unpinned", verdict.unverified)

    def test_registry_append_makes_old_observation_stale(self):
        self.registry.register(lease(suffix="d"))
        verdict = verify_registry_witness(
            self.witness, self.registry, now=1010,
            expected_witness_digest=self.witness.witness_digest,
        )
        self.assertEqual(verdict.state, "stale")
        self.assertIn("registry_head_changed", verdict.reasons)
        self.assertFalse(verdict.execution_authorized)

    def test_revoke_after_snapshot_is_not_current(self):
        self.registry.revoke(self.value.lease_digest)
        verdict = verify_registry_witness(
            self.witness, self.registry, now=1010,
            expected_witness_digest=self.witness.witness_digest,
        )
        self.assertEqual(verdict.state, "revoked")
        self.assertIn("lease_revoked", verdict.reasons)

    def test_tampered_witness_or_registry_is_unverifiable(self):
        forged = LeaseRegistryWitness(
            self.witness.schema_version, self.witness.lease_digest,
            self.witness.observed_state, self.witness.record_sequence,
            D("f"), self.witness.observed_at, self.witness.witness_digest,
        )
        with self.assertRaises(RegistryWitnessError):
            verify_registry_witness(forged, self.registry, now=1010,
                                    expected_witness_digest=self.witness.witness_digest)
        path = Path(self.root) / "leases.jsonl"
        value = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        value["plan_id"] = "tampered"
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        verdict = verify_registry_witness(self.witness, self.registry, now=1010)
        self.assertEqual(verdict.state, "unverifiable")

    def test_missing_registry_history_is_unverifiable(self):
        (Path(self.root) / "leases.jsonl").unlink()
        verdict = verify_registry_witness(self.witness, self.registry, now=1010)
        self.assertEqual(verdict.state, "unverifiable")
        self.assertFalse(verdict.execution_authorized)


if __name__ == "__main__":
    unittest.main()
