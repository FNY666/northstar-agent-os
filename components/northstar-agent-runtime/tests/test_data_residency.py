"""Tests for data_residency: regional pinning and transfer control."""

import ast
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data_residency import (
    VERSION,
    SCHEMA,
    AUDIT_SCHEMA,
    JURISDICTIONS,
    REGION_JURISDICTION,
    DATA_CLASSES,
    TRANSFER_BASES,
    POLICY_DIGEST,
    DataResidency,
    DataResidencyError,
    SeqOrderError,
    BadInputError,
    UnknownJurisdictionError,
    UnknownRegionError,
    DuplicateRegionError,
    UnknownDataClassError,
    UnknownPinError,
    DuplicatePinError,
    TransferDeniedError,
    InvalidBasisError,
    data_residency_audit_event,
)

MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "data_residency.py")
_STDLIB_ALLOW = {
    "hashlib", "json", "re", "threading", "dataclasses", "typing",
    "__future__", "ast",
}


class PinsTest(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "data-residency.v1")
        self.assertEqual(SCHEMA, "northstar.data-residency.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_policy_digest_stable(self):
        self.assertTrue(POLICY_DIGEST.startswith("sha256:"))
        self.assertEqual(len(POLICY_DIGEST), 7 + 64)

    def test_vocabulary_nonempty(self):
        self.assertIn("eu", JURISDICTIONS)
        self.assertIn("personal", DATA_CLASSES)
        self.assertIn("scc", TRANSFER_BASES)
        self.assertEqual(REGION_JURISDICTION["eu-west-1"], "eu")
        self.assertEqual(REGION_JURISDICTION["cn-north-1"], "cn")

    def test_stdlib_only(self):
        tree = ast.parse(open(MODULE_PATH).read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        self.assertTrue(imported <= _STDLIB_ALLOW, imported - _STDLIB_ALLOW)


class RegionTest(unittest.TestCase):
    def test_register_region(self):
        mgr = DataResidency()
        rec = mgr.register_region("ap-southeast-2", "sg", 1, label="Sydney")
        self.assertEqual(rec.jurisdiction, "sg")
        self.assertTrue(rec.verify())
        self.assertIn("ap-southeast-2", mgr.region_codes())

    def test_register_duplicate(self):
        mgr = DataResidency()
        with self.assertRaises(DuplicateRegionError):
            mgr.register_region("eu-west-1", "eu", 1)
        # failed mutation consumed its seq
        rec = mgr.register_region("xx-north-9", "other", 2)
        self.assertEqual(rec.region_code, "xx-north-9")

    def test_register_bad_inputs(self):
        mgr = DataResidency()
        with self.assertRaises(UnknownJurisdictionError):
            mgr.register_region("xx-1", "atlantis", 1)
        with self.assertRaises(BadInputError):
            mgr.register_region("BAD CODE!", "eu", 2)
        with self.assertRaises(BadInputError):
            mgr.register_region("", "eu", 3)
        with self.assertRaises(UnknownRegionError):
            mgr.region("no-such-region")


class PinTest(unittest.TestCase):
    def test_pin_roundtrip(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        self.assertTrue(pin.verify())
        self.assertEqual(pin.pin_id, "pin-1")
        self.assertEqual(mgr.residency(pin.pin_id), "eu-west-1")
        self.assertEqual(mgr.pin_record(pin.pin_id).subject_id, "alice")

    def test_pin_unknown_region_and_class(self):
        mgr = DataResidency()
        with self.assertRaises(UnknownRegionError):
            mgr.pin("alice", "nowhere-1", 1)
        with self.assertRaises(UnknownDataClassError):
            mgr.pin("alice", "eu-west-1", 2, "ultra-secret")
        with self.assertRaises(UnknownPinError):
            mgr.pin_record("pin-999")

    def test_pin_duplicate_active(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        with self.assertRaises(DuplicatePinError):
            mgr.pin("alice", "eu-central-1", 2, "personal")
        # different class may coexist
        other = mgr.pin("alice", "eu-central-1", 3, "non-personal")
        self.assertEqual(len(mgr.pins_of("alice")), 2)

    def test_pin_seq_discipline(self):
        mgr = DataResidency()
        mgr.pin("alice", "eu-west-1", 1)
        with self.assertRaises(SeqOrderError):
            mgr.pin("bob", "eu-west-1", 1)  # rewind
        with self.assertRaises(SeqOrderError):
            mgr.pin("bob", "eu-west-1", True)  # bool
        with self.assertRaises(SeqOrderError):
            mgr.pin("bob", "eu-west-1", -2)  # negative
        with self.assertRaises(SeqOrderError):
            mgr.pin("bob", "eu-west-1", 1.5)  # float
        pin = mgr.pin("bob", "eu-west-1", 2)
        self.assertEqual(pin.pin_id, "pin-2")  # failures consumed their seqs

    def test_pin_chain(self):
        mgr = DataResidency()
        p1 = mgr.pin("alice", "eu-west-1", 1, "personal")
        self.assertEqual(p1.prev_digest, "")
        p2 = mgr.pin("alice", "eu-west-1", 2, "sensitive")
        self.assertEqual(p2.prev_digest, p1.record_digest)


class MigrateTest(unittest.TestCase):
    def test_migrate_same_jurisdiction(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        mig = mgr.migrate(pin.pin_id, "eu-central-1", 2)
        self.assertIsNone(mig.transfer_basis)
        self.assertTrue(mig.verify())
        self.assertEqual(mgr.residency(pin.pin_id), "eu-central-1")
        self.assertEqual(len(mgr.migration_history(pin.pin_id)), 1)

    def test_migrate_denied_without_basis(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        with self.assertRaises(TransferDeniedError):
            mgr.migrate(pin.pin_id, "us-east-1", 2)  # eu->us needs basis

    def test_migrate_with_basis(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        mig = mgr.migrate(pin.pin_id, "us-east-1", 2, "scc")
        self.assertEqual(mig.transfer_basis, "scc")
        self.assertEqual(mgr.residency(pin.pin_id), "us-east-1")

    def test_migrate_wrong_basis(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        with self.assertRaises(InvalidBasisError):
            mgr.migrate(pin.pin_id, "us-east-1", 2, "pinkie-promise")
        # basis not accepted for this pair
        with self.assertRaises(TransferDeniedError):
            mgr.migrate(pin.pin_id, "us-east-1", 3, "adequacy")

    def test_migrate_china_requires_assessment(self):
        mgr = DataResidency()
        pin = mgr.pin("zhang", "cn-north-1", 1, "personal")
        with self.assertRaises(TransferDeniedError):
            mgr.migrate(pin.pin_id, "eu-west-1", 2, "scc")
        mig = mgr.migrate(pin.pin_id, "eu-west-1", 3, "security-assessment")
        self.assertEqual(mgr.residency(pin.pin_id), "eu-west-1")

    def test_migrate_bad_inputs(self):
        mgr = DataResidency()
        pin = mgr.pin("alice", "eu-west-1", 1, "personal")
        with self.assertRaises(UnknownPinError):
            mgr.migrate("pin-404", "us-east-1", 2, "scc")
        with self.assertRaises(UnknownRegionError):
            mgr.migrate(pin.pin_id, "nowhere-9", 3, "scc")
        with self.assertRaises(BadInputError):
            mgr.migrate(pin.pin_id, "eu-west-1", 4)  # same region

    def test_migrate_nonpersonal_free(self):
        mgr = DataResidency()
        pin = mgr.pin("metrics", "cn-north-1", 1, "non-personal")
        mig = mgr.migrate(pin.pin_id, "us-east-1", 2)
        self.assertEqual(mgr.residency(pin.pin_id), "us-east-1")


class PolicyViewTest(unittest.TestCase):
    def test_transfer_allowed_view(self):
        mgr = DataResidency()
        allowed, bases = mgr.transfer_allowed("eu-west-1", "eu-central-1", "personal")
        self.assertTrue(allowed)
        self.assertIsNone(bases)
        allowed, bases = mgr.transfer_allowed("eu-west-1", "us-east-1", "personal")
        self.assertFalse(allowed)
        self.assertIn("scc", bases)
        allowed, bases = mgr.transfer_allowed("eu-west-1", "us-east-1", "personal", "scc")
        self.assertTrue(allowed)

    def test_policy_table_inspectable(self):
        mgr = DataResidency()
        table = mgr.policy_table()
        self.assertTrue(len(table) > 5)
        entry = next(e for e in table
                     if (e["from"], e["to"], e["class"]) == ("cn", "*", "personal"))
        self.assertIn("security-assessment", entry["bases"])


class AuditTest(unittest.TestCase):
    def test_audit_shapes(self):
        mgr = DataResidency()
        mgr.pin("alice", "eu-west-1", 1)
        with self.assertRaises(TransferDeniedError):
            mgr.migrate(mgr.pins_of("alice")[0].pin_id, "us-east-1", 2)
        kinds = [e["kind"] for e in mgr.audit_log()]
        self.assertEqual(kinds, ["data-pinned", "rejected"])
        ev = data_residency_audit_event("data-pinned", 1, pin_id="pin-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], "data_residency")
        with self.assertRaises(DataResidencyError):
            data_residency_audit_event("bogus", 1)
        summary = mgr.audit(3)
        self.assertEqual(summary["state"]["pins"], 1)
        self.assertEqual(summary["state"]["policy_digest"], POLICY_DIGEST)

    def test_concurrency(self):
        mgr = DataResidency()
        errors = []

        def work(i):
            try:
                mgr.pin(f"subj-{i}", "eu-west-1", i + 1)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # seqs collide under concurrency; at least the manager stays consistent
        total_pins = sum(len(mgr.pins_of(f"subj-{i}")) for i in range(8))
        self.assertEqual(total_pins + len(errors), 8)
        for pin in list(mgr._pins.values()):
            self.assertTrue(pin.verify())


class MainTest(unittest.TestCase):
    def test_main(self):
        from data_residency import main
        main()


if __name__ == "__main__":
    unittest.main()
