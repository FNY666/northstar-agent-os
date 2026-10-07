"""Targeted tests for the seed data manager interface."""

import ast
import unittest
from pathlib import Path

from seed_manager import (
    AUDIT_SCHEMA,
    FIELD_KINDS,
    KIND_FACTORY_DEFINED,
    KIND_RESET,
    KIND_SEEDED,
    SEED_MANAGER_SCHEMA,
    SEED_MANAGER_VERSION,
    BadFactoryError,
    BadFieldError,
    BadSeedError,
    DuplicateFactoryError,
    FieldSpec,
    KIND_CONST,
    KIND_SEQ,
    KIND_CHOICE,
    KIND_INT_RANGE,
    KIND_TEXT,
    SeedError,
    SeedManager,
    SeqOrderError,
    UnknownFactoryError,
    UnknownRunError,
    main,
    seed_manager_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "seed_manager.py"


def _fields():
    return (
        FieldSpec("name", KIND_TEXT, {"length": 4, "alphabet": "ab"}),
        FieldSpec("age", KIND_INT_RANGE, {"lo": 1, "hi": 5}),
        FieldSpec("role", KIND_CHOICE, {"options": ["x", "y"]}),
        FieldSpec("n", KIND_SEQ, {"start": 10, "step": 5}),
        FieldSpec("active", KIND_CONST, {"value": False}),
    )


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SEED_MANAGER_VERSION, "seed-manager.v1")
        self.assertEqual(SEED_MANAGER_SCHEMA, "northstar.seed-manager.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(
            FIELD_KINDS, ("const", "seq", "choice", "int_range", "text")
        )

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "threading", "dataclasses", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestDefine(unittest.TestCase):
    def test_define_roundtrip(self):
        mgr = SeedManager()
        record = mgr.define_factory("users", "User", _fields(), seq=1)
        self.assertTrue(record.verify())
        self.assertEqual(mgr.factory("users").digest, record.digest)
        self.assertEqual(mgr.factory_ids(), ("users",))

    def test_define_duplicate_refused(self):
        mgr = SeedManager()
        mgr.define_factory("users", "User", _fields(), seq=1)
        with self.assertRaises(DuplicateFactoryError):
            mgr.define_factory("users", "User", _fields(), seq=2)

    def test_define_bad_field_kind_refused(self):
        with self.assertRaises(BadFieldError):
            FieldSpec("x", "oracle", {})

    def test_define_bad_field_params_refused(self):
        with self.assertRaises(BadFieldError):
            FieldSpec("n", KIND_SEQ, {"start": 1, "step": 0})
        with self.assertRaises(BadFieldError):
            FieldSpec("a", KIND_INT_RANGE, {"lo": 9, "hi": 9})
        with self.assertRaises(BadFieldError):
            FieldSpec("c", KIND_CHOICE, {"options": []})
        with self.assertRaises(BadFactoryError):
            SeedManager().define_factory("f", "M", (), seq=1)

    def test_factory_unknown_refused(self):
        with self.assertRaises(UnknownFactoryError):
            SeedManager().factory("nope")


class TestSeed(unittest.TestCase):
    def test_seed_happy_path(self):
        mgr = SeedManager()
        mgr.define_factory("users", "User", _fields(), seq=1)
        run = mgr.seed("users", 4, seq=2)
        self.assertTrue(run.verify())
        rows = mgr.fixtures_of(run.run_id)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(f.verify() for f in rows))
        self.assertEqual([f.index for f in rows], [0, 1, 2, 3])
        self.assertEqual(rows[0].values["n"], 10)
        self.assertEqual(rows[2].values["n"], 20)
        self.assertEqual(run.fixture_ids, tuple(f.fixture_id for f in rows))
        for f in rows:
            self.assertEqual(f.factory_digest, mgr.factory("users").digest)

    def test_seed_deterministic_across_instances(self):
        def build():
            mgr = SeedManager(seed=42)
            mgr.define_factory("u", "U", _fields(), seq=1)
            return mgr.seed("u", 5, seq=2)

        self.assertEqual(build().digest, build().digest)

    def test_seed_unknown_factory_refused(self):
        with self.assertRaises(UnknownFactoryError):
            SeedManager().seed("ghost", 2, seq=1)

    def test_seed_bad_count_refused(self):
        mgr = SeedManager()
        mgr.define_factory("u", "U", _fields(), seq=1)
        seq = 2
        for bad in (0, -1, True, "3", 2.0):
            with self.assertRaises(BadSeedError):
                mgr.seed("u", bad, seq=seq)
            seq += 1  # failed mutations consume their seq

    def test_failed_mutation_consumes_seq(self):
        mgr = SeedManager()
        mgr.define_factory("u", "U", _fields(), seq=1)
        with self.assertRaises(UnknownFactoryError):
            mgr.seed("ghost", 2, seq=2)
        with self.assertRaises(SeqOrderError):
            mgr.seed("u", 2, seq=2)


class TestReset(unittest.TestCase):
    def test_reset_clears_fixtures_keeps_factories(self):
        mgr = SeedManager()
        mgr.define_factory("u", "U", _fields(), seq=1)
        run = mgr.seed("u", 3, seq=2)
        reset = mgr.reset(seq=3)
        self.assertEqual(reset.cleared_count, 3)
        self.assertTrue(reset.verify())
        self.assertEqual(mgr.fixture_count(), 0)
        self.assertEqual(mgr.run_ids(), ())
        self.assertEqual(mgr.factory_ids(), ("u",))
        with self.assertRaises(UnknownRunError):
            mgr.run(run.run_id)


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_order_enforced(self):
        mgr = SeedManager()
        mgr.define_factory("u", "U", _fields(), seq=1)
        with self.assertRaises(SeqOrderError):
            mgr.seed("u", 1, seq=1)
        with self.assertRaises(SeqOrderError):
            mgr.reset(seq=0)

    def test_audit_shapes(self):
        mgr = SeedManager()
        mgr.define_factory("u", "U", _fields(), seq=1)
        mgr.seed("u", 2, seq=2)
        mgr.reset(seq=3)
        kinds = [e["kind"] for e in mgr.audit_log()]
        self.assertEqual(kinds, [KIND_FACTORY_DEFINED, KIND_SEEDED, KIND_RESET])
        for event in mgr.audit_log():
            self.assertEqual(event["schema"], AUDIT_SCHEMA)
            self.assertEqual(event["module_version"], SEED_MANAGER_VERSION)
        with self.assertRaises(SeedError):
            seed_manager_audit_event("bogus", seq=9)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
