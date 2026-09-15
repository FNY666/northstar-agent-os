"""Rollback detection for the lease registry (high-water mark)."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_readiness_lease_registry import (
    EvidenceReadinessLeaseRegistry,
    LeaseRegistryError,
)
from test_evidence_readiness_lease_registry import lease


class LeaseRegistryRollbackTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.registry = EvidenceReadinessLeaseRegistry(self.root)
        self.log = self.root / "leases.jsonl"
        self.meta = self.root / "leases.meta"

    def _truncate(self, count):
        lines = self.log.read_text(encoding="utf-8").splitlines(True)
        self.log.write_text("".join(lines[:count]), encoding="utf-8")

    def _write_meta(self, payload):
        self.meta.write_text(json.dumps(payload), encoding="utf-8")

    def test_truncated_revocation_does_not_read_as_active(self):
        item = lease(suffix="a")
        self.registry.register(item)
        self.registry.revoke(item.lease_digest)
        self._truncate(1)
        verdict = self.registry.inspect(item.lease_digest, now=1010)
        self.assertNotEqual(verdict.state, "active")
        self.assertEqual(verdict.state, "unverifiable")

    def test_truncated_registration_is_not_reported_as_unknown(self):
        first = lease(suffix="a")
        second = lease(suffix="b")
        self.registry.register(first)
        self.registry.register(second)
        self._truncate(1)
        verdict = self.registry.inspect(second.lease_digest, now=1010)
        self.assertEqual(verdict.state, "unverifiable")

    def test_missing_mark_beside_existing_log_is_unverifiable(self):
        item = lease(suffix="a")
        self.registry.register(item)
        self.meta.unlink()
        verdict = self.registry.inspect(item.lease_digest, now=1010)
        self.assertEqual(verdict.state, "unverifiable")
    def test_mark_ahead_of_log_is_unverifiable(self):
        item = lease(suffix="a")
        self.registry.register(item)
        payload = json.loads(self.meta.read_text(encoding="utf-8"))
        payload["high_water"] = {"sequence": 5, "head_digest": "sha256:" + "0" * 64}
        self._write_meta(payload)
        verdict = self.registry.inspect(item.lease_digest, now=1010)
        self.assertEqual(verdict.state, "unverifiable")

    def test_log_ahead_of_mark_is_repaired(self):
        item = lease(suffix="a")
        self.registry.register(item)
        self.registry.revoke(item.lease_digest)
        payload = json.loads(self.meta.read_text(encoding="utf-8"))
        first = json.loads(self.log.read_text(encoding="utf-8").splitlines()[0])
        payload["high_water"] = {"sequence": 1, "head_digest": first["record_digest"]}
        self._write_meta(payload)
        verdict = self.registry.inspect(item.lease_digest, now=1010)
        self.assertEqual(verdict.state, "revoked")
        repaired = json.loads(self.meta.read_text(encoding="utf-8"))
        self.assertEqual(repaired["high_water"]["sequence"], 2)

    def test_whole_store_removal_reads_as_unknown(self):
        item = lease(suffix="a")
        self.registry.register(item)
        self.log.unlink()
        self.meta.unlink()
        verdict = self.registry.inspect(item.lease_digest, now=1010)
        self.assertEqual(verdict.state, "unknown")

    def test_revocation_stays_monotonic_after_repair(self):
        item = lease(suffix="a")
        self.registry.register(item)
        self.registry.revoke(item.lease_digest)
        payload = json.loads(self.meta.read_text(encoding="utf-8"))
        first = json.loads(self.log.read_text(encoding="utf-8").splitlines()[0])
        payload["high_water"] = {"sequence": 1, "head_digest": first["record_digest"]}
        self._write_meta(payload)
        self.registry.inspect(item.lease_digest, now=1010)
        with self.assertRaises(LeaseRegistryError):
            self.registry.revoke(item.lease_digest)
        self.assertEqual(self.registry.inspect(item.lease_digest, now=1020).state, "revoked")
