"""Tests for structured_log: level gating, fields, with_fields, drain."""

import ast
import math
import unittest
from pathlib import Path

import structured_log
from structured_log import (
    DEBUG, ERROR, INFO, WARN,
    FieldsError, LevelError, StructuredLog, StructuredLogError,
    structured_log_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(structured_log.STRUCTURED_LOG_VERSION, "structured-log.v1")

    def test_schema_pin(self):
        self.assertEqual(structured_log.SCHEMA_PIN, "northstar.structured-log.v1")


class TestConstructor(unittest.TestCase):
    def test_default_level_is_info(self):
        self.assertEqual(StructuredLog().min_level, INFO)

    def test_bad_level_refused(self):
        for bad in ("verbose", "", None, 20, b"info"):
            with self.assertRaises(LevelError):
                StructuredLog(min_level=bad)

    def test_bad_max_buffer_refused(self):
        for bad in (0, -1, True, "10", 2.5):
            with self.assertRaises(StructuredLogError):
                StructuredLog(max_buffer=bad)

    def test_bad_emitter_refused(self):
        with self.assertRaises(StructuredLogError):
            StructuredLog(emitter="not-callable")


class TestEmission(unittest.TestCase):
    def test_info_happy_path(self):
        log = StructuredLog()
        rec = log.info("hello", 0)
        self.assertEqual(rec.level, INFO)
        self.assertEqual(rec.message, "hello")
        self.assertEqual(rec.seq, 0)
        self.assertTrue(rec.record_digest.startswith("sha256:"))
        self.assertTrue(rec.verify())
        self.assertEqual(log.records(), (rec,))
        self.assertEqual(log.emitted_count(), 1)

    def test_all_levels_emitted(self):
        log = StructuredLog(min_level=DEBUG)
        recs = [log.debug("d", 0), log.info("i", 1), log.warn("w", 2), log.error("e", 3)]
        self.assertEqual([r.level for r in recs], [DEBUG, INFO, WARN, ERROR])
        self.assertEqual(log.emitted_count(), 4)
        self.assertTrue(all(r.verify() for r in recs))

    def test_below_min_dropped_and_counted(self):
        log = StructuredLog(min_level=WARN)
        rec = log.debug("quiet", 0)
        self.assertTrue(rec.verify())
        self.assertEqual(log.records(), ())
        self.assertEqual(log.dropped_count(), 1)
        self.assertEqual(log.emitted_count(), 0)

    def test_boundary_not_dropped(self):
        log = StructuredLog(min_level=WARN)
        log.warn("edge", 0)
        self.assertEqual(log.dropped_count(), 0)
        self.assertEqual(log.emitted_count(), 1)

    def test_digest_determinism(self):
        a = StructuredLog().info("same", 5, {"x": 1})
        b = StructuredLog().info("same", 5, {"x": 1})
        self.assertEqual(a.record_digest, b.record_digest)

    def test_digest_binds_content(self):
        base = StructuredLog().info("msg", 0, {"x": 1})
        other = StructuredLog().info("msg", 0, {"x": 2})
        self.assertNotEqual(base.record_digest, other.record_digest)

    def test_bool_vs_int_distinct(self):
        a = StructuredLog().info("m", 0, {"flag": True})
        b = StructuredLog().info("m", 0, {"flag": 1})
        self.assertNotEqual(a.record_digest, b.record_digest)

    def test_field_order_normalized(self):
        a = StructuredLog().info("m", 0, {"b": 1, "a": 2})
        b = StructuredLog().info("m", 0, {"a": 2, "b": 1})
        self.assertEqual(a.record_digest, b.record_digest)


class TestValidation(unittest.TestCase):
    def setUp(self):
        self.log = StructuredLog(min_level=DEBUG)

    def test_empty_message_refused(self):
        for bad in ("", None, 42, b"msg"):
            with self.assertRaises(StructuredLogError):
                self.log.info(bad, 0)

    def test_bad_seq_refused(self):
        for bad in (-1, True, 1.5, "0"):
            with self.assertRaises(StructuredLogError):
                self.log.info("m", bad)

    def test_non_mapping_fields_refused(self):
        with self.assertRaises(FieldsError):
            self.log.info("m", 0, [("a", 1)])

    def test_non_str_key_refused(self):
        for bad in ({1: "x"}, {"": "x"}):
            with self.assertRaises(FieldsError):
                self.log.info("m", 0, bad)

    def test_nan_inf_refused(self):
        for bad in (math.nan, math.inf, -math.inf):
            with self.assertRaises(FieldsError):
                self.log.info("m", 0, {"v": bad})

    def test_huge_int_refused(self):
        with self.assertRaises(FieldsError):
            self.log.info("m", 0, {"v": 2 ** 60})
        with self.assertRaises(FieldsError):
            self.log.info("m", 0, {"v": 1e60})

    def test_object_value_refused(self):
        with self.assertRaises(FieldsError):
            self.log.info("m", 0, {"v": object()})

    def test_nested_values(self):
        rec = self.log.info("m", 0, {"a": [1, "x", None], "b": {"c": 2.5}})
        self.assertTrue(rec.verify())
        self.assertEqual(rec.fields_dict()["b"], {"c": 2.5})


class TestWithFields(unittest.TestCase):
    def test_merge_and_override(self):
        log = StructuredLog()
        child = log.with_fields(service="edge", shard=3)
        rec = child.info("m", 0, {"shard": 4, "lat": 10})
        self.assertEqual(rec.fields_dict(), {"service": "edge", "shard": 4, "lat": 10})
        self.assertTrue(rec.verify())

    def test_parent_not_mutated(self):
        log = StructuredLog()
        log.with_fields(service="edge")
        self.assertEqual(log.bound_fields, {})

    def test_chained(self):
        child = StructuredLog().with_fields(a=1).with_fields(b=2)
        rec = child.info("m", 0)
        self.assertEqual(rec.fields_dict(), {"a": 1, "b": 2})

    def test_validation_at_creation(self):
        with self.assertRaises(FieldsError):
            StructuredLog().with_fields(v=math.nan)
        with self.assertRaises(FieldsError):
            StructuredLog().with_fields({1: "x"})

    def test_with_min_level(self):
        log = StructuredLog(min_level=DEBUG).with_fields(a=1)
        quiet = log.with_min_level(ERROR)
        quiet.debug("d", 0)
        self.assertEqual(quiet.dropped_count(), 1)
        self.assertEqual(quiet.bound_fields, {"a": 1})


class TestDrain(unittest.TestCase):
    def test_drain_roundtrip(self):
        log = StructuredLog()
        log.info("a", 0)
        log.warn("b", 1)
        report = log.drain(2)
        self.assertEqual(report.drained, 2)
        self.assertEqual(report.first_seq, 0)
        self.assertEqual(report.last_seq, 1)
        self.assertEqual(log.records(), ())
        self.assertEqual(report.as_dict()["drained"], 2)

    def test_drain_empty(self):
        report = StructuredLog().drain(0)
        self.assertEqual(report.drained, 0)
        self.assertIsNone(report.first_seq)

    def test_drain_bad_seq(self):
        with self.assertRaises(StructuredLogError):
            StructuredLog().drain(-1)

    def test_max_buffer_ring(self):
        log = StructuredLog(max_buffer=2)
        log.info("a", 0)
        log.info("b", 1)
        log.info("c", 2)
        seqs = [r.seq for r in log.records()]
        self.assertEqual(seqs, [1, 2])
        self.assertEqual(log.emitted_count(), 3)


class TestEmitter(unittest.TestCase):
    def test_injected_emitter_called(self):
        seen = []
        log = StructuredLog(emitter=seen.append)
        rec = log.info("m", 0)
        self.assertEqual(seen, [rec])
        self.assertEqual(log.records(), ())

    def test_emitter_not_called_for_drops(self):
        seen = []
        log = StructuredLog(min_level=ERROR, emitter=seen.append)
        log.info("m", 0)
        self.assertEqual(seen, [])


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        ev = structured_log_audit_event("emitted", 1, level="info",
                                        record_digest="sha256:abc")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "emitted")
        self.assertEqual(ev["level"], "info")
        self.assertEqual(ev["record_digest"], "sha256:abc")

    def test_unknown_kind_refused(self):
        with self.assertRaises(StructuredLogError):
            structured_log_audit_event("nope", 0)

    def test_bad_seq_refused(self):
        with self.assertRaises(StructuredLogError):
            structured_log_audit_event("emitted", -1)


class TestRecords(unittest.TestCase):
    def test_frozen(self):
        rec = StructuredLog().info("m", 0)
        with self.assertRaises(Exception):
            rec.message = "changed"  # type: ignore

    def test_fields_dict_is_copy(self):
        rec = StructuredLog().info("m", 0, {"a": 1})
        d = rec.fields_dict()
        d["a"] = 99
        self.assertEqual(rec.fields_dict()["a"], 1)

    def test_as_dict_shape(self):
        rec = StructuredLog().info("m", 7, {"a": 1})
        d = rec.as_dict()
        self.assertEqual(d["schema"], "northstar.structured-log.v1")
        self.assertEqual(d["version"], "structured-log.v1")
        self.assertEqual(d["seq"], 7)
        self.assertEqual(d["fields"], {"a": 1})

    def test_stdlib_only(self):
        path = Path(__file__).resolve().parent.parent / "structured_log.py"
        tree = ast.parse(path.read_text())
        allowed = {"__future__", "hashlib", "math", "threading", "dataclasses",
                   "typing", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
