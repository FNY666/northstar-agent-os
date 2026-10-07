"""Tests for multi_tenancy: create / isolate / migrate. 15 cases."""

import ast
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from multi_tenancy import (
    MULTI_TENANCY_VERSION,
    MULTI_TENANCY_SCHEMA,
    AUDIT_SCHEMA,
    BadTenantError,
    DuplicateTenantError,
    UnknownTenantError,
    BadIsolationError,
    BadScopeError,
    IncompatibleScopeError,
    DuplicateIsolationError,
    BadMigrationError,
    SameModelError,
    DowngradeRefusedError,
    SeqOrderError,
    MultiTenancyError,
    MultiTenancy,
    multi_tenancy_audit_event,
)


def _stdlib_only(path):
    tree = ast.parse(open(path).read())
    allowed = {
        "hashlib", "json", "math", "threading", "dataclasses",
        "typing", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(MULTI_TENANCY_VERSION, "multi-tenancy.v1")
        self.assertEqual(MULTI_TENANCY_SCHEMA, "northstar.multi-tenancy.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        _stdlib_only(os.path.join(os.path.dirname(__file__), "..", "multi_tenancy.py"))


class TestCreate(unittest.TestCase):
    def test_create_roundtrip(self):
        mt = MultiTenancy()
        rec = mt.create("acme", 0, name="Acme Corp", plan="team")
        self.assertEqual(rec.tenant_id, "acme")
        self.assertEqual(rec.plan, "team")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.verify())

    def test_create_duplicate_refused(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        with self.assertRaises(DuplicateTenantError):
            mt.create("acme", 1)

    def test_create_bad_inputs(self):
        mt = MultiTenancy()
        for bad, seq in [("", 0), (123, 1), (None, 2)]:
            with self.assertRaises((BadTenantError, MultiTenancyError)):
                mt.create(bad, seq)
        with self.assertRaises(BadTenantError):
            mt.create("x", 3, plan="platinum")
        with self.assertRaises(SeqOrderError):
            mt.create("y", -1)

    def test_seq_rewind_and_bool_refused(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        with self.assertRaises(SeqOrderError):
            mt.create("other", 0)
        with self.assertRaises(SeqOrderError):
            mt.create("other2", True)


class TestIsolate(unittest.TestCase):
    def test_isolate_silo_happy_path(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        rec = mt.isolate("acme", 1, "silo", ("compute", "data", "network", "keys"))
        self.assertEqual(rec.model, "silo")
        self.assertTrue(rec.verify())
        self.assertEqual(mt.isolation("acme").model, "silo")

    def test_isolate_incompatible_scopes_refused(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        # pool pins exactly the data scope
        with self.assertRaises(IncompatibleScopeError):
            mt.isolate("acme", 1, "pool", ("data", "keys"))
        # bridge requires data + keys minimum
        with self.assertRaises(IncompatibleScopeError):
            mt.isolate("acme", 2, "bridge", ("data",))
        with self.assertRaises(BadScopeError):
            mt.isolate("acme", 3, "pool", ("data", "vpn"))
        with self.assertRaises(BadIsolationError):
            mt.isolate("acme", 4, "castle", ("data",))

    def test_isolate_duplicate_refused(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        mt.isolate("acme", 1, "pool", ("data",))
        with self.assertRaises(DuplicateIsolationError):
            mt.isolate("acme", 2, "pool", ("data",))

    def test_isolate_unknown_tenant(self):
        mt = MultiTenancy()
        with self.assertRaises(UnknownTenantError):
            mt.isolate("ghost", 0, "pool", ("data",))


class TestMigrate(unittest.TestCase):
    def test_migrate_upgrade_allowed(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        mt.isolate("acme", 1, "pool", ("data",))
        rec = mt.migrate("acme", 2, "silo")
        self.assertFalse(rec.downgrade)
        self.assertEqual(rec.from_model, "pool")
        self.assertEqual(rec.to_model, "silo")
        self.assertTrue(rec.verify())
        self.assertEqual(mt.isolation("acme").model, "silo")

    def test_migrate_downgrade_needs_ack(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        mt.isolate("acme", 1, "silo", ("compute", "data", "network", "keys"))
        with self.assertRaises(DowngradeRefusedError):
            mt.migrate("acme", 2, "pool")
        rec = mt.migrate("acme", 3, "pool", downgrade_ack=True)
        self.assertTrue(rec.downgrade)
        self.assertEqual(mt.isolation("acme").model, "pool")
        # scopes collapse to the pool pin
        self.assertEqual(mt.isolation("acme").scopes, ("data",))

    def test_migrate_same_model_refused(self):
        mt = MultiTenancy()
        mt.create("acme", 0)
        mt.isolate("acme", 1, "bridge", ("data", "keys"))
        with self.assertRaises(SameModelError):
            mt.migrate("acme", 2, "bridge")


class TestAuditAndViews(unittest.TestCase):
    def test_audit_shapes_and_name_not_leaked(self):
        mt = MultiTenancy()
        mt.create("acme", 0, name="Secret Name")
        mt.isolate("acme", 1, "pool", ("data",))
        log = mt.audit_log()
        kinds = {e["kind"] for e in log}
        self.assertIn("tenant-created", kinds)
        self.assertIn("tenant-isolated", kinds)
        for event in log:
            blob = str(event)
            self.assertNotIn("Secret Name", blob)
            self.assertEqual(event["schema"], "audit.ndjson/1")
        with self.assertRaises(MultiTenancyError):
            multi_tenancy_audit_event("bogus-kind", 0, "acme")

    def test_views_and_snapshot(self):
        mt = MultiTenancy()
        mt.create("b", 0)
        mt.create("a", 1)
        self.assertEqual(mt.tenant_ids(), ("a", "b"))
        self.assertEqual(mt.tenant("a").tenant_id, "a")
        self.assertIsNone(mt.isolation("a"))
        snap = mt.as_dict()
        self.assertEqual(snap["version"], "multi-tenancy.v1")
        self.assertNotIn("name", str(snap["tenants"]))
        summary = mt.audit(2)
        self.assertEqual(summary["tenants"], 2)
        self.assertTrue(summary["digest"].startswith("sha256:"))
        with self.assertRaises(UnknownTenantError):
            mt.tenant("ghost")

    def test_main_selfcheck(self):
        import io
        from contextlib import redirect_stdout
        import multi_tenancy

        buf = io.StringIO()
        with redirect_stdout(buf):
            multi_tenancy.main()
        self.assertIn("multi-tenancy OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
