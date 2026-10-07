"""Targeted tests for the SCIM provisioning interface."""

import ast
import unittest
from pathlib import Path

from scim_provisioning import (
    AUDIT_SCHEMA,
    SCIM_PROVISIONING_SCHEMA,
    SCIM_PROVISIONING_VERSION,
    KIND_SYNCED,
    KIND_DEPROVISIONED,
    KIND_GROUP_CREATED,
    KIND_MEMBER_ADDED,
    KIND_MEMBER_REMOVED,
    SCIMError,
    BadUserError,
    UnknownUserError,
    BadGroupError,
    UnknownGroupError,
    DuplicateGroupError,
    AlreadyDeprovisionedError,
    SeqOrderError,
    SCIMProvisioning,
    compute_record_digest,
    scim_provisioning_audit_event,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "scim_provisioning.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SCIM_PROVISIONING_VERSION, "scim-provisioning.v1")
        self.assertEqual(SCIM_PROVISIONING_SCHEMA, "northstar.scim-provisioning.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "dataclasses", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestSync(unittest.TestCase):
    def test_sync_creates_user(self):
        mgr = SCIMProvisioning()
        rec = mgr.sync("u-1", 1, {"userName": "alice", "emails": ["a@x.io"]})
        self.assertEqual(rec.version, 1)
        self.assertEqual(rec.status, "active")
        self.assertEqual(compute_record_digest(rec), rec.record_digest)

    def test_sync_versions_chain(self):
        mgr = SCIMProvisioning()
        r1 = mgr.sync("u-1", 1, {"userName": "alice"})
        r2 = mgr.sync("u-1", 2, {"userName": "alice", "title": "eng"})
        self.assertEqual(r2.version, 2)
        self.assertEqual(r2.prev_digest, r1.record_digest)

    def test_sync_bad_attributes(self):
        mgr = SCIMProvisioning()
        with self.assertRaises(BadUserError):
            mgr.sync("u-1", 1, {"unknownAttr": "x"})
        with self.assertRaises(BadUserError):
            mgr.sync("u-1", 2, {"emails": "not-a-list"})
        with self.assertRaises(BadUserError):
            mgr.sync("u-1", 3, {"emails": ["no-at-sign"]})

    def test_sync_seq_ordering(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 5, {"userName": "alice"})
        with self.assertRaises(SeqOrderError):
            mgr.sync("u-1", 5, {"userName": "alice"})
        with self.assertRaises(SeqOrderError):
            mgr.sync("u-1", 3, {"userName": "alice"})
        with self.assertRaises(SeqOrderError):
            mgr.sync("u-1", True, {"userName": "alice"})


class TestDeprovision(unittest.TestCase):
    def test_deprovision_terminal(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice"})
        dep = mgr.deprovision("u-1", 2, "offboarded")
        self.assertEqual(compute_record_digest(dep), dep.record_digest)
        self.assertTrue(mgr.is_deprovisioned("u-1"))
        with self.assertRaises(AlreadyDeprovisionedError):
            mgr.deprovision("u-1", 3)

    def test_deprovision_unknown_user(self):
        mgr = SCIMProvisioning()
        with self.assertRaises(UnknownUserError):
            mgr.deprovision("ghost", 1)

    def test_sync_on_deprovisioned_refused(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice"})
        mgr.deprovision("u-1", 2)
        with self.assertRaises(AlreadyDeprovisionedError):
            mgr.sync("u-1", 3, {"userName": "alice"})

    def test_reprovision_clears_flag(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice"})
        mgr.deprovision("u-1", 2)
        rec = mgr.reprovision("u-1", 3, {"userName": "alice"})
        self.assertEqual(rec.version, 2)
        self.assertFalse(mgr.is_deprovisioned("u-1"))


class TestGroups(unittest.TestCase):
    def test_group_lifecycle(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice"})
        grp = mgr.create_group("g-eng", 2, "Engineering")
        self.assertEqual(compute_record_digest(grp), grp.record_digest)
        mem = mgr.add_member("g-eng", "u-1", 3)
        self.assertEqual(mem.action, "added")
        self.assertEqual(mgr.groups("u-1"), ("g-eng",))
        self.assertEqual(mgr.group_members("g-eng"), ("u-1",))
        mgr.remove_member("g-eng", "u-1", 4)
        self.assertEqual(mgr.groups("u-1"), ())

    def test_group_refusals(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice"})
        mgr.create_group("g-eng", 2, "Engineering")
        with self.assertRaises(DuplicateGroupError):
            mgr.create_group("g-eng", 3, "Dup")
        with self.assertRaises(UnknownGroupError):
            mgr.add_member("ghost", "u-1", 4)
        with self.assertRaises(UnknownUserError):
            mgr.add_member("g-eng", "ghost", 4)
        mgr.add_member("g-eng", "u-1", 5)
        with self.assertRaises(DuplicateGroupError):
            mgr.add_member("g-eng", "u-1", 6)
        mgr.remove_member("g-eng", "u-1", 7)
        with self.assertRaises(SCIMError):
            mgr.remove_member("g-eng", "u-1", 8)

    def test_add_deprovisioned_member_refused(self):
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice"})
        mgr.create_group("g-eng", 2, "Engineering")
        mgr.deprovision("u-1", 3)
        with self.assertRaises(AlreadyDeprovisionedError):
            mgr.add_member("g-eng", "u-1", 4)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        evt = scim_provisioning_audit_event(KIND_SYNCED, 1, user_id="u-1")
        self.assertEqual(evt["schema"], AUDIT_SCHEMA)
        self.assertEqual(evt["kind"], KIND_SYNCED)
        with self.assertRaises(SCIMError):
            scim_provisioning_audit_event("bogus", 1)
        # Attribute values banned from the audit boundary.
        with self.assertRaises(SCIMError):
            scim_provisioning_audit_event(
                KIND_SYNCED, 2, user_id="u-1", attributes={"userName": "alice"}
            )
        mgr = SCIMProvisioning()
        mgr.sync("u-1", 1, {"userName": "alice", "emails": ["a@x.io"]})
        log = mgr.audit_log()
        self.assertEqual(len(log), 1)
        self.assertNotIn("attributes", log[0]["detail"])

    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
