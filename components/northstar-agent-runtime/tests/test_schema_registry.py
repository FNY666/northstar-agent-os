"""Targeted tests for the schema registry interface."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

from schema_registry import (
    AUDIT_SCHEMA,
    COMPATIBILITY_MODES,
    COMPAT_BACKWARD,
    COMPAT_FORWARD,
    COMPAT_FULL,
    COMPAT_NONE,
    KIND_REJECTED,
    KIND_SCHEMA_EVOLVED,
    KIND_SCHEMA_REGISTERED,
    KIND_SUBJECT_DELETED,
    SCHEMA_REGISTRY_SCHEMA,
    SCHEMA_REGISTRY_VERSION,
    SCHEMA_TYPES,
    BadCompatibilityError,
    BadSchemaError,
    BadSubjectError,
    CompatibilityReport,
    DeletedSubjectError,
    DuplicateSubjectError,
    IncompatibleSchemaError,
    SchemaRecord,
    SchemaRegistry,
    SchemaRegistryError,
    SeqOrderError,
    SubjectDeletion,
    TypeMismatchError,
    UnknownSubjectError,
    main,
    schema_registry_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "schema_registry.py"

V1 = {"properties": {"id": {"type": "string"}}, "required": ["id"]}
V2_BACKWARD_OK = {
    "properties": {"id": {"type": "string"}, "note": {"type": "string"}},
    "required": ["id"],
}
V2_BACKWARD_BAD = {
    "properties": {"id": {"type": "string"}, "total": {"type": "number"}},
    "required": ["id", "total"],
}


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SCHEMA_REGISTRY_VERSION, "schema-registry.v1")
        self.assertEqual(SCHEMA_REGISTRY_SCHEMA, "northstar.schema-registry.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(SCHEMA_TYPES, ("avro", "protobuf", "json-schema"))
        self.assertEqual(
            COMPATIBILITY_MODES, ("none", "backward", "forward", "full")
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

    def test_main_self_check(self):
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("schema-registry OK", result.stdout)


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()

    def test_register_roundtrip(self):
        rec = self.reg.register("orders", "json-schema", V1, seq=1)
        self.assertIsInstance(rec, SchemaRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.subject, "orders")
        self.assertEqual(rec.version, 1)
        self.assertEqual(rec.schema_type, "json-schema")
        self.assertTrue(rec.schema_digest.startswith("sha256:"))
        self.assertEqual(self.reg.latest("orders"), rec)
        self.assertEqual(self.reg.versions("orders"), (rec,))
        self.assertEqual(self.reg.subjects(), ("orders",))

    def test_register_accepts_json_string(self):
        rec = self.reg.register("a", "avro", '{"properties": {}}', seq=1)
        self.assertEqual(rec.version, 1)
        self.assertTrue(rec.verify())

    def test_register_duplicate_subject_refused(self):
        self.reg.register("orders", "json-schema", V1, seq=1)
        with self.assertRaises(DuplicateSubjectError):
            self.reg.register("orders", "json-schema", V2_BACKWARD_OK, seq=2)

    def test_register_bad_subjects(self):
        for idx, bad in enumerate(("", "   ", "has space", "has\nnewline")):
            with self.assertRaises(BadSubjectError, msg=bad):
                self.reg.register(bad, "json-schema", V1, seq=idx + 1)

    def test_register_bad_schema_inputs(self):
        with self.assertRaises(BadSchemaError):
            self.reg.register("s1", "yaml", V1, seq=1)
        with self.assertRaises(BadSchemaError):
            self.reg.register("s2", "avro", "not-json{", seq=2)
        with self.assertRaises(BadSchemaError):
            self.reg.register("s3", "avro", [1, 2], seq=3)
        with self.assertRaises(BadSchemaError):
            self.reg.register(
                "s4", "avro",
                {"properties": {"x": {"score": 1.5}}}, seq=4,
            )  # floats refused


class TestEvolve(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()
        self.reg.register("orders", "json-schema", V1, seq=1)

    def test_evolve_backward_compatible(self):
        rec = self.reg.evolve("orders", V2_BACKWARD_OK, seq=2)
        self.assertEqual(rec.version, 2)
        self.assertTrue(rec.verify())
        self.assertEqual(self.reg.latest("orders"), rec)

    def test_evolve_incompatible_refused(self):
        with self.assertRaises(IncompatibleSchemaError):
            self.reg.evolve("orders", V2_BACKWARD_BAD, seq=2)
        # latest unchanged, version still 1
        self.assertEqual(self.reg.latest("orders").version, 1)

    def test_evolve_forward_mode(self):
        # V2_BACKWARD_OK drops no required field of V1 -> forward OK too
        rec = self.reg.evolve(
            "orders", V2_BACKWARD_OK, seq=2, compatibility=COMPAT_FORWARD
        )
        self.assertEqual(rec.version, 2)

    def test_evolve_forward_violation(self):
        self.reg.evolve("orders", V2_BACKWARD_OK, seq=2)
        # drop "id", which latest v2 requires, to break forward
        bad = {
            "properties": {"note": {"type": "string"}},
            "required": [],
        }
        with self.assertRaises(IncompatibleSchemaError):
            self.reg.evolve("orders", bad, seq=3, compatibility=COMPAT_FORWARD)

    def test_evolve_full_mode(self):
        with self.assertRaises(IncompatibleSchemaError):
            self.reg.evolve("orders", V2_BACKWARD_BAD, seq=2,
                            compatibility=COMPAT_FULL)

    def test_evolve_none_mode_skips_checks(self):
        rec = self.reg.evolve(
            "orders", V2_BACKWARD_BAD, seq=2, compatibility=COMPAT_NONE
        )
        self.assertEqual(rec.version, 2)

    def test_evolve_identical_schema_idempotent(self):
        rec = self.reg.evolve("orders", V1, seq=2)
        self.assertEqual(rec.version, 1)
        self.assertEqual(self.reg.versions("orders"), (rec,))
        # seq not consumed: next mutation may reuse seq 2
        rec2 = self.reg.evolve("orders", V2_BACKWARD_OK, seq=2)
        self.assertEqual(rec2.version, 2)

    def test_evolve_unknown_subject(self):
        with self.assertRaises(UnknownSubjectError):
            self.reg.evolve("nope", V1, seq=1)

    def test_evolve_bad_compatibility(self):
        with self.assertRaises(BadCompatibilityError):
            self.reg.evolve("orders", V2_BACKWARD_OK, seq=2,
                            compatibility="sideways")


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()
        self.reg.register("orders", "json-schema", V1, seq=1)

    def test_check_compatible_as_data(self):
        report = self.reg.check("orders", V2_BACKWARD_OK, seq=2)
        self.assertIsInstance(report, CompatibilityReport)
        self.assertTrue(report.compatible)
        self.assertEqual(report.issues, ())
        self.assertEqual(report.checked_against_version, 1)

    def test_check_incompatible_as_data_with_issues(self):
        report = self.reg.check("orders", V2_BACKWARD_BAD, seq=2)
        self.assertFalse(report.compatible)
        self.assertTrue(report.issues)
        self.assertIn("total", report.issues[0])

    def test_check_is_pure_view(self):
        before = self.reg._last_seq
        self.reg.check("orders", V2_BACKWARD_OK, seq=2)
        self.assertEqual(self.reg._last_seq, before)
        audit_kinds = [e["kind"] for e in self.reg.audit_log()]
        self.assertNotIn("schema.checked", audit_kinds)

    def test_check_unknown_subject(self):
        with self.assertRaises(UnknownSubjectError):
            self.reg.check("nope", V1, seq=2)


class TestDelete(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()
        self.reg.register("orders", "json-schema", V1, seq=1)

    def test_delete_terminal(self):
        tomb = self.reg.delete_subject("orders", seq=2, reason="retired")
        self.assertIsInstance(tomb, SubjectDeletion)
        self.assertTrue(tomb.verify())
        self.assertEqual(self.reg.subjects(), ())
        with self.assertRaises(DeletedSubjectError):
            self.reg.latest("orders")
        with self.assertRaises(DeletedSubjectError):
            self.reg.register("orders", "json-schema", V1, seq=3)

    def test_delete_unknown_subject(self):
        with self.assertRaises(UnknownSubjectError):
            self.reg.delete_subject("nope", seq=2)

    def test_delete_double_refused(self):
        self.reg.delete_subject("orders", seq=2)
        with self.assertRaises(DeletedSubjectError):
            self.reg.delete_subject("orders", seq=3)


class TestSeqDiscipline(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()
        self.reg.register("orders", "json-schema", V1, seq=1)

    def test_seq_rewind_refused(self):
        with self.assertRaises(SeqOrderError):
            self.reg.evolve("orders", V2_BACKWARD_OK, seq=1)

    def test_seq_bool_refused(self):
        with self.assertRaises(SchemaRegistryError):
            self.reg.evolve("orders", V2_BACKWARD_OK, seq=True)

    def test_failed_mutation_consumes_seq(self):
        with self.assertRaises(IncompatibleSchemaError):
            self.reg.evolve("orders", V2_BACKWARD_BAD, seq=2)
        # seq 2 is burned: next mutation must use seq 3
        with self.assertRaises(SeqOrderError):
            self.reg.evolve("orders", V2_BACKWARD_OK, seq=2)
        rec = self.reg.evolve("orders", V2_BACKWARD_OK, seq=3)
        self.assertEqual(rec.version, 2)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()

    def test_audit_shapes(self):
        self.reg.register("orders", "json-schema", V1, seq=1)
        self.reg.evolve("orders", V2_BACKWARD_OK, seq=2)
        self.reg.delete_subject("orders", seq=3)
        kinds = [e["kind"] for e in self.reg.audit_log()]
        self.assertEqual(
            kinds,
            [KIND_SCHEMA_REGISTERED, KIND_SCHEMA_EVOLVED, KIND_SUBJECT_DELETED],
        )
        for event in self.reg.audit_log():
            self.assertEqual(event["schema"], "audit.ndjson/1")
            # raw schema text never crosses the audit boundary
            self.assertNotIn("schema_text", event["detail"])

    def test_rejected_audited(self):
        self.reg.register("orders", "json-schema", V1, seq=1)
        with self.assertRaises(DuplicateSubjectError):
            self.reg.register("orders", "json-schema", V1, seq=2)
        self.assertEqual(
            self.reg.audit_log()[-1]["kind"], KIND_REJECTED
        )

    def test_bad_audit_kind(self):
        with self.assertRaises(SchemaRegistryError):
            schema_registry_audit_event("bogus.kind", seq=1)


class TestViews(unittest.TestCase):
    def setUp(self):
        self.reg = SchemaRegistry()
        self.reg.register("b", "avro", V1, seq=1)
        self.reg.register("a", "avro", V1, seq=2)

    def test_subjects_sorted(self):
        self.assertEqual(self.reg.subjects(), ("a", "b"))

    def test_version_addressable(self):
        self.reg.evolve("a", V2_BACKWARD_OK, seq=3)
        v1 = self.reg.version("a", 1)
        v2 = self.reg.version("a", 2)
        self.assertEqual((v1.version, v2.version), (1, 2))
        self.assertTrue(v1.verify() and v2.verify())
        with self.assertRaises(BadSchemaError):
            self.reg.version("a", 9)

    def test_cross_instance_digest_determinism(self):
        other = SchemaRegistry()
        r1 = self.reg.latest("a")
        r2 = other.register("a", "avro", V1, seq=2)
        self.assertEqual(r1.schema_digest, r2.schema_digest)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
