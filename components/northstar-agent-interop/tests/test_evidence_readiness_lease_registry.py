"""Tests for durable readiness-lease registration and revocation."""
from __future__ import annotations

import json
import multiprocessing
import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_readiness_lease import EvidenceReadinessLease, SCHEMA as LEASE_SCHEMA
from plan_evidence_decision import derive_plan_id
from evidence_readiness_lease_registry import (
    LeaseRegistryError,
    LeaseRegistryRecord,
    LeaseRegistryVerdict,
    EvidenceReadinessLeaseRegistry,
)

D = lambda char: "sha256:" + char * 64


def lease(*, issued=1000, expires=1060, suffix="a"):
    draft = EvidenceReadinessLease(
        LEASE_SCHEMA,
        derive_plan_id(D("b")),
        D(suffix),
        D("b"),
        D("c"),
        issued,
        expires,
        False,
        "",
    )
    return EvidenceReadinessLease(
        draft.schema_version, draft.plan_id, draft.decision_digest,
        draft.manifest_digest, draft.gate_digest, draft.issued_at,
        draft.expires_at, False, draft.computed_digest,
    )


def register_worker(root, wire, result_path):
    try:
        registry = EvidenceReadinessLeaseRegistry(root)
        record = registry.register(EvidenceReadinessLease.from_dict(wire))
        result = ("ok", record.lease_digest)
    except Exception as exc:
        result = ("error", type(exc).__name__, str(exc))
    Path(result_path).write_text(json.dumps(result), encoding="utf-8")


class RegistryFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="lease-registry-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.registry = EvidenceReadinessLeaseRegistry(self.root)
        self.lease = lease()


class RegistryBasics(RegistryFixture):
    def test_register_and_inspect_active_lease(self):
        record = self.registry.register(self.lease)
        self.assertIsInstance(record, LeaseRegistryRecord)
        self.assertEqual(record.action, "registered")
        verdict = self.registry.inspect(self.lease.lease_digest, now=1010)
        self.assertIsInstance(verdict, LeaseRegistryVerdict)
        self.assertEqual(verdict.state, "active")
        self.assertFalse(verdict.execution_authorized)
        self.assertEqual(verdict.lease_digest, self.lease.lease_digest)

    def test_duplicate_registration_is_idempotent(self):
        first = self.registry.register(self.lease)
        second = self.registry.register(self.lease)
        self.assertEqual(first, second)
        self.assertEqual(len(self.registry.records), 1)

    def test_registration_survives_restart(self):
        self.registry.register(self.lease)
        restarted = EvidenceReadinessLeaseRegistry(self.root)
        self.assertEqual(restarted.inspect(self.lease.lease_digest, now=1010).state, "active")
        self.assertEqual(restarted.records[0].lease_digest, self.lease.lease_digest)

    def test_expiry_is_reported_without_authorization(self):
        self.registry.register(self.lease)
        verdict = self.registry.inspect(self.lease.lease_digest, now=1061)
        self.assertEqual(verdict.state, "expired")
        self.assertIn("lease_expired", verdict.reasons)
        self.assertFalse(verdict.execution_authorized)

    def test_unknown_lease_is_not_active(self):
        verdict = self.registry.inspect(D("f"), now=1010)
        self.assertEqual(verdict.state, "unknown")
        self.assertFalse(verdict.execution_authorized)

    def test_record_wire_form_is_strict(self):
        record = self.registry.register(self.lease)
        self.assertEqual(LeaseRegistryRecord.from_dict(record.to_dict()), record)
        with self.assertRaises(LeaseRegistryError):
            LeaseRegistryRecord.from_dict({**record.to_dict(), "extra": True})
        with self.assertRaises(LeaseRegistryError):
            LeaseRegistryRecord.from_dict({})

    def test_registry_stores_only_lease_metadata(self):
        self.registry.register(self.lease)
        raw = (Path(self.root) / "leases.jsonl").read_text(encoding="utf-8")
        for forbidden in ("prompt", "command", "event_id", "secret", "provider_output"):
            self.assertNotIn(forbidden, raw)
        self.assertNotIn("execution_authorized", raw)

    def test_bad_lease_digest_is_refused(self):
        forged = EvidenceReadinessLease(
            self.lease.schema_version, self.lease.plan_id,
            self.lease.decision_digest, self.lease.manifest_digest,
            self.lease.gate_digest, self.lease.issued_at,
            self.lease.expires_at, False, D("f"),
        )
        with self.assertRaises(LeaseRegistryError):
            self.registry.register(forged)


class RevocationTests(RegistryFixture):
    def test_revoke_active_lease_and_keep_revoked_after_restart(self):
        self.registry.register(self.lease)
        record = self.registry.revoke(self.lease.lease_digest)
        self.assertEqual(record.action, "revoked")
        self.assertEqual(self.registry.inspect(self.lease.lease_digest, now=1010).state, "revoked")
        restarted = EvidenceReadinessLeaseRegistry(self.root)
        verdict = restarted.inspect(self.lease.lease_digest, now=1010)
        self.assertEqual(verdict.state, "revoked")
        self.assertFalse(verdict.execution_authorized)

    def test_repeated_and_unknown_revocation_are_refused(self):
        with self.assertRaises(LeaseRegistryError):
            self.registry.revoke(self.lease.lease_digest)
        self.registry.register(self.lease)
        self.registry.revoke(self.lease.lease_digest)
        with self.assertRaises(LeaseRegistryError):
            self.registry.revoke(self.lease.lease_digest)

    def test_revoked_lease_cannot_be_registered_again(self):
        self.registry.register(self.lease)
        self.registry.revoke(self.lease.lease_digest)
        with self.assertRaises(LeaseRegistryError):
            self.registry.register(self.lease)


class RecoveryTests(RegistryFixture):
    def test_truncated_tail_is_ignored(self):
        self.registry.register(self.lease)
        with (Path(self.root) / "leases.jsonl").open("ab") as handle:
            handle.write(b'{"schema_version":"northstar.readiness-lease-registry.v1"')
        restored = EvidenceReadinessLeaseRegistry(self.root)
        self.assertEqual(restored.verify().state, "replayable")
        self.assertEqual(restored.inspect(self.lease.lease_digest, now=1010).state, "active")

    def test_complete_malformed_line_blocks_mutation(self):
        self.registry.register(self.lease)
        with (Path(self.root) / "leases.jsonl").open("ab") as handle:
            handle.write(b'{"bad":"record"}\n')
        restored = EvidenceReadinessLeaseRegistry(self.root)
        self.assertEqual(restored.verify().state, "unverifiable")
        with self.assertRaises(LeaseRegistryError):
            restored.register(lease(suffix="d"))

    def test_tampered_record_is_unverifiable(self):
        self.registry.register(self.lease)
        path = Path(self.root) / "leases.jsonl"
        value = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        value["plan_id"] = "plan-evidence:tampered"
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        self.assertEqual(EvidenceReadinessLeaseRegistry(self.root).verify().state, "unverifiable")

    def test_missing_history_after_registration_is_unverifiable(self):
        self.registry.register(self.lease)
        (Path(self.root) / "leases.jsonl").unlink()
        restored = EvidenceReadinessLeaseRegistry(self.root)
        self.assertEqual(restored.verify().state, "unverifiable")
        self.assertEqual(restored.inspect(self.lease.lease_digest, now=1010).state, "unverifiable")


class ConcurrencyTests(RegistryFixture):
    def test_concurrent_first_registration_is_idempotent(self):
        root = Path(self.root) / "concurrent"
        context = multiprocessing.get_context("fork")
        result_paths = [root / ("result-%d.json" % index) for index in range(2)]
        processes = [context.Process(
            target=register_worker,
            args=(str(root), self.lease.to_dict(), str(path)),
        ) for path in result_paths]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
        results = [json.loads(path.read_text(encoding="utf-8")) for path in result_paths]
        self.assertEqual(sum(result[0] == "ok" for result in results), 2)
        self.assertTrue(all(not process.is_alive() for process in processes))
        registry = EvidenceReadinessLeaseRegistry(root)
        self.assertEqual(len(registry.records), 1)
        self.assertEqual(registry.verify().state, "replayable")


if __name__ == "__main__":
    unittest.main()


class LeaseLabelIdentityTests(RegistryFixture):
    def test_a_lease_label_must_match_its_own_manifest_digest(self):
        draft = EvidenceReadinessLease(
            self.lease.schema_version, "plan-evidence:0000000000000000",
            self.lease.decision_digest, self.lease.manifest_digest,
            self.lease.gate_digest, self.lease.issued_at,
            self.lease.expires_at, False, "",
        )
        inconsistent = EvidenceReadinessLease(
            draft.schema_version, draft.plan_id, draft.decision_digest,
            draft.manifest_digest, draft.gate_digest, draft.issued_at,
            draft.expires_at, False, draft.computed_digest,
        )
        self.assertNotEqual(
            inconsistent.plan_id, derive_plan_id(inconsistent.manifest_digest)
        )
        with self.assertRaises(LeaseRegistryError):
            self.registry.register(inconsistent)
