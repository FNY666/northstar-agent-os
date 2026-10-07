"""Tests for data_lineage.py: provenance DAG for ML data."""

import ast
import unittest
from pathlib import Path

import data_lineage
from data_lineage import (
    DATA_LINEAGE_SCHEMA,
    DATA_LINEAGE_VERSION,
    DataLineage,
    DataLineageError,
    DuplicateIdError,
    ExternalSource,
    LineageNode,
    LineagePath,
    LineageRecord,
    LineageVerification,
    LineageVerificationError,
    SeqCausalityError,
    UnknownParentError,
    data_lineage_audit_event,
)


class PinsTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(DATA_LINEAGE_VERSION, "data-lineage.v1")

    def test_schema_pin(self):
        self.assertEqual(DATA_LINEAGE_SCHEMA, "northstar.data-lineage.v1")


class RegisterSourceTest(unittest.TestCase):
    def setUp(self):
        self.lin = DataLineage()

    def test_happy_path(self):
        src = self.lin.register_source("s3://bucket/raw", 0)
        self.assertIsInstance(src, ExternalSource)
        self.assertEqual(src.name, "s3://bucket/raw")
        self.assertTrue(src.digest.startswith("sha256:"))
        self.assertEqual(src.schema, DATA_LINEAGE_SCHEMA)
        self.assertEqual(self.lin.sources(), ("s3://bucket/raw",))

    def test_digest_deterministic(self):
        a = DataLineage().register_source("x", 0)
        b = DataLineage().register_source("x", 0)
        self.assertEqual(a.digest, b.digest)

    def test_duplicate_rejected(self):
        self.lin.register_source("x", 0)
        with self.assertRaises(DuplicateIdError):
            self.lin.register_source("x", 1)

    def test_name_must_be_nonempty_str(self):
        with self.assertRaises(ValueError):
            self.lin.register_source("", 0)
        with self.assertRaises(TypeError):
            self.lin.register_source(123, 0)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            self.lin.register_source("x", True)
        with self.assertRaises(ValueError):
            self.lin.register_source("x", -1)


class TrackTest(unittest.TestCase):
    def setUp(self):
        self.lin = DataLineage()
        self.lin.register_source("raw", 0)

    def test_happy_path(self):
        rec = self.lin.track("cleaned", ("raw",), 1, transform="filter")
        self.assertIsInstance(rec, LineageRecord)
        self.assertEqual(rec.parents, ("raw",))
        self.assertEqual(rec.transform, "filter")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.verify_digest())

    def test_no_transform(self):
        rec = self.lin.track("cleaned", ("raw",), 1)
        self.assertIsNone(rec.transform)
        self.assertTrue(rec.verify_digest())

    def test_multi_parent_join(self):
        self.lin.register_source("vendor", 1)
        self.lin.track("cleaned", ("raw",), 2)
        rec = self.lin.track("features", ("cleaned", "vendor"), 3, transform="join")
        self.assertEqual(rec.parents, ("cleaned", "vendor"))
        self.assertTrue(rec.verify_digest())

    def test_duplicate_data_id(self):
        self.lin.track("cleaned", ("raw",), 1)
        with self.assertRaises(DuplicateIdError):
            self.lin.track("cleaned", ("raw",), 2)

    def test_unknown_parent(self):
        with self.assertRaises(UnknownParentError):
            self.lin.track("x", ("nope",), 1)

    def test_self_parent(self):
        with self.assertRaises(DataLineageError):
            self.lin.track("x", ("x", "raw"), 1)

    def test_duplicate_sources(self):
        with self.assertRaises(ValueError):
            self.lin.track("x", ("raw", "raw"), 1)

    def test_empty_sources(self):
        with self.assertRaises(ValueError):
            self.lin.track("x", (), 1)

    def test_seq_causality(self):
        self.lin.track("a", ("raw",), 5)
        with self.assertRaises(SeqCausalityError):
            self.lin.track("b", ("a",), 5)  # equal, not strictly after
        with self.assertRaises(SeqCausalityError):
            self.lin.track("b", ("a",), 4)  # before parent

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            self.lin.track("", ("raw",), 1)
        with self.assertRaises(TypeError):
            self.lin.track("x", "raw", 1)  # str is not an iterable of sources
        with self.assertRaises(TypeError):
            self.lin.track("x", ("raw",), True)


class LineageTest(unittest.TestCase):
    def setUp(self):
        self.lin = DataLineage()
        self.lin.register_source("raw", 0)
        self.lin.register_source("vendor", 1)
        self.lin.track("cleaned", ("raw",), 2, transform="filter")
        self.lin.track("features", ("cleaned", "vendor"), 3, transform="join")
        self.lin.track("model", ("features",), 4, transform="train")

    def test_linear_chain(self):
        path = self.lin.lineage("cleaned")
        self.assertIsInstance(path, LineagePath)
        self.assertEqual(path.ids(), ("raw", "cleaned"))
        self.assertEqual([n.depth for n in path.nodes], [0, 1])

    def test_diamond_order_deterministic(self):
        path = self.lin.lineage("model")
        self.assertEqual(
            path.ids(),
            ("raw", "vendor", "cleaned", "features", "model"),
        )
        self.assertEqual([n.depth for n in path.nodes], [0, 0, 1, 2, 3])

    def test_lineage_of_source(self):
        path = self.lin.lineage("raw")
        self.assertEqual(path.ids(), ("raw",))
        self.assertEqual(path.nodes[0].depth, 0)

    def test_unknown_id(self):
        with self.assertRaises(DataLineageError):
            self.lin.lineage("ghost")

    def test_children_view(self):
        self.assertEqual(self.lin.children("cleaned"), ("features",))
        self.assertEqual(self.lin.children("raw"), ("cleaned",))
        self.assertEqual(self.lin.children("model"), ())

    def test_views(self):
        self.assertEqual(self.lin.sources(), ("raw", "vendor"))
        self.assertEqual(self.lin.datasets(), ("cleaned", "features", "model"))
        self.assertEqual(len(self.lin), 3)
        self.assertIsNone(self.lin.record("ghost"))
        self.assertEqual(self.lin.record("cleaned").transform, "filter")


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.lin = DataLineage()
        self.lin.register_source("raw", 0)
        self.lin.track("cleaned", ("raw",), 1)

    def test_clean_verifies(self):
        report = self.lin.verify()
        self.assertIsInstance(report, LineageVerification)
        self.assertTrue(report.ok)
        self.assertEqual(report.records_checked, 1)
        self.assertEqual(report.issues, ())
        self.lin.verify_strict()  # must not raise

    def test_tampered_digest_detected(self):
        recs = list(self.lin._records.values())
        object.__setattr__(recs[0], "digest", "sha256:" + "ff" * 32)
        report = self.lin.verify()
        self.assertFalse(report.ok)
        self.assertTrue(any("digest mismatch" in i for i in report.issues))
        with self.assertRaises(LineageVerificationError):
            self.lin.verify_strict()

    def test_dangling_parent_detected(self):
        # Simulate a corrupted store: drop the source but keep the record.
        del self.lin._sources["raw"]
        del self.lin._seqs["raw"]
        report = self.lin.verify()
        self.assertFalse(report.ok)
        self.assertTrue(any("dangling parent" in i for i in report.issues))

    def test_seq_causality_violation_detected(self):
        rec = self.lin._records["cleaned"]
        object.__setattr__(rec, "seq", 0)  # not after parent seq 0
        report = self.lin.verify()
        self.assertFalse(report.ok)
        self.assertTrue(any("causality" in i for i in report.issues))


class AuditEventTest(unittest.TestCase):
    def setUp(self):
        self.lin = DataLineage()
        self.lin.register_source("raw", 0)

    def test_shape(self):
        ev = data_lineage_audit_event("tracked", self.lin, 2)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "data-lineage.tracked")
        self.assertEqual(ev["module"], DATA_LINEAGE_SCHEMA)
        self.assertEqual(ev["version"], DATA_LINEAGE_VERSION)
        self.assertEqual(ev["seq"], 2)
        self.assertEqual(ev["sources"], 1)
        self.assertEqual(ev["datasets"], 0)

    def test_all_kinds(self):
        for kind in ("source-registered", "tracked", "verified", "verification-failed"):
            ev = data_lineage_audit_event(kind, self.lin, 0)
            self.assertEqual(ev["kind"], f"data-lineage.{kind}")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            data_lineage_audit_event("nope", self.lin, 0)

    def test_bad_seq_and_lineage(self):
        with self.assertRaises(ValueError):
            data_lineage_audit_event("tracked", self.lin, -1)
        with self.assertRaises(TypeError):
            data_lineage_audit_event("tracked", object(), 0)


class HouseStyleTest(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(data_lineage.__file__).read_text()
        tree = ast.parse(src)
        allowed = {"hashlib", "hmac", "json", "threading", "dataclasses", "typing", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_frozen_records(self):
        lin = DataLineage()
        src = lin.register_source("raw", 0)
        with self.assertRaises(Exception):
            src.name = "evil"  # frozen dataclass
        rec = lin.track("c", ("raw",), 1)
        with self.assertRaises(Exception):
            rec.seq = 99

    def test_main_self_check(self):
        data_lineage.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
