"""Tests for data_pipeline: extract/transform/load bookkeeping (15+ cases)."""

import ast
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import data_pipeline as dp
from data_pipeline import DataPipeline


def make_pipe():
    return DataPipeline()


def sample_rows():
    return [
        {"id": 1, "name": "a", "age": 30},
        {"id": 2, "name": "b", "age": 17},
        {"id": 3, "name": "c", "age": None},
    ]


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(dp.DATA_PIPELINE_VERSION, "data-pipeline.v1")
        self.assertEqual(dp.DATA_PIPELINE_SCHEMA, "northstar.data-pipeline.v1")
        self.assertEqual(dp.AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        with open(dp.__file__) as fh:
            tree = ast.parse(fh.read())
        allowed = {"__future__", "hashlib", "json", "dataclasses",
                   "threading", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)


class TestExtract(unittest.TestCase):
    def test_extract_roundtrip_and_verify(self):
        pipe = make_pipe()
        ext = pipe.extract("crm", 1, sample_rows())
        self.assertEqual(ext.extract_id, "ext-1")
        self.assertEqual(ext.source_name, "crm")
        self.assertEqual(ext.row_count, 3)
        self.assertTrue(ext.verify())
        self.assertEqual(pipe.get_extract("ext-1"), ext)
        self.assertTrue(ext.record_digest.startswith("sha256:"))

    def test_extract_empty_rows(self):
        pipe = make_pipe()
        ext = pipe.extract("src", 1, [])
        self.assertEqual(ext.row_count, 0)
        self.assertTrue(ext.verify())

    def test_extract_bad_inputs(self):
        pipe = make_pipe()
        with self.assertRaises(dp.DataPipelineError):
            pipe.extract("", 1, [])  # empty source
        with self.assertRaises(dp.BadRecordError):
            pipe.extract("s", 2, ["not-a-mapping"])
        with self.assertRaises(dp.DataPipelineError):
            pipe.extract("s", 3, [{"x": 1.5}])  # float refused
        with self.assertRaises(dp.DataPipelineError):
            pipe.extract("s", 4, [{"x": 2 ** 53}])  # unsafe int refused
        with self.assertRaises(dp.UnknownExtractError):
            pipe.get_extract("ext-999")

    def test_extract_ids_monotonic(self):
        pipe = make_pipe()
        pipe.extract("s", 1, [])
        ext2 = pipe.extract("s", 2, [])
        self.assertEqual(ext2.extract_id, "ext-2")
        self.assertEqual(ext2.prev_digest,
                         pipe.get_extract("ext-1").record_digest)


class TestTransform(unittest.TestCase):
    def _pipe_with_extract(self, seq_start=1):
        pipe = make_pipe()
        ext = pipe.extract("crm", seq_start, sample_rows())
        return pipe, ext

    def test_transform_unknown_extract(self):
        pipe = make_pipe()
        with self.assertRaises(dp.UnknownExtractError):
            pipe.transform("ext-999", 1, [{"op": "select", "fields": ["id"]}])

    def test_transform_select(self):
        pipe, _ = self._pipe_with_extract()
        trn = pipe.transform("ext-1", 2,
                             [{"op": "select", "fields": ["id"]}])
        self.assertEqual(trn.row_count, 3)
        for row in trn.rows:
            self.assertEqual(dict(row), {"id": dict(row)["id"]})
        self.assertTrue(trn.verify())

    def test_transform_rename(self):
        pipe, _ = self._pipe_with_extract()
        trn = pipe.transform("ext-1", 2,
                             [{"op": "rename", "mapping": {"name": "full"}}])
        self.assertIn(("full", "a"), trn.rows[0])
        self.assertNotIn("name", dict(trn.rows[0]))
        self.assertTrue(trn.verify())

    def test_transform_filter(self):
        pipe, _ = self._pipe_with_extract()
        trn = pipe.transform(
            "ext-1", 2,
            [{"op": "filter", "field": "age", "op_filter": "gt", "value": 18}])
        self.assertEqual(trn.row_count, 1)
        self.assertEqual(dict(trn.rows[0])["id"], 1)
        trn2 = pipe.transform(
            "ext-1", 3,
            [{"op": "filter", "field": "name", "op_filter": "ne", "value": "a"}])
        self.assertEqual(trn2.row_count, 2)

    def test_transform_add_and_drop_null(self):
        pipe, _ = self._pipe_with_extract()
        trn = pipe.transform("ext-1", 2, [
            {"op": "drop_null", "field": "age"},
            {"op": "add", "field": "src", "value": "crm"},
        ])
        self.assertEqual(trn.row_count, 2)
        self.assertEqual(dict(trn.rows[0])["src"], "crm")

    def test_transform_bad_ops(self):
        pipe, _ = self._pipe_with_extract()
        with self.assertRaises(dp.BadOperationError):
            pipe.transform("ext-1", 2, [{"op": "join"}])  # unknown op
        with self.assertRaises(dp.BadOperationError):
            pipe.transform("ext-1", 3, [])  # empty ops
        with self.assertRaises(dp.BadOperationError):
            pipe.transform("ext-1", 4, [{"op": "select", "fields": []}])
        with self.assertRaises(dp.BadOperationError):
            pipe.transform("ext-1", 5, [{"op": "filter", "field": "age",
                                         "op_filter": "between", "value": 1}])
        with self.assertRaises(dp.UnknownTransformError):
            pipe.get_transform("trn-999")


class TestLoad(unittest.TestCase):
    def test_load_roundtrip(self):
        pipe = make_pipe()
        pipe.extract("crm", 1, sample_rows())
        trn = pipe.transform("ext-1", 2, [{"op": "select", "fields": ["id"]}])
        lod = pipe.load("trn-1", 3, "warehouse.users")
        self.assertEqual(lod.load_id, "lod-1")
        self.assertEqual(lod.transform_id, "trn-1")
        self.assertEqual(lod.target, "warehouse.users")
        self.assertEqual(lod.row_count, 3)
        self.assertTrue(lod.rows_digest.startswith("sha256:"))
        self.assertTrue(lod.verify())
        self.assertEqual(pipe.get_load("lod-1"), lod)

    def test_load_unknown_transform(self):
        pipe = make_pipe()
        with self.assertRaises(dp.UnknownTransformError):
            pipe.load("trn-999", 1, "warehouse.x")


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_rewind_refused_and_burned(self):
        pipe = make_pipe()
        pipe.extract("s", 1, [])
        with self.assertRaises(dp.SeqOrderError):
            pipe.extract("s", 1, [])
        with self.assertRaises(dp.SeqOrderError):
            pipe.extract("s", 0, [])
        with self.assertRaises(dp.DataPipelineError):
            pipe.extract("s", True, [])  # bool seq refused
        ext = pipe.extract("s", 2, [])
        self.assertEqual(ext.extract_id, "ext-2")

    def test_failed_mutation_burns_seq(self):
        pipe = make_pipe()
        with self.assertRaises(dp.DataPipelineError):
            pipe.extract("", 1, [])  # fails, burns seq 1
        ext = pipe.extract("s", 2, [])
        self.assertEqual(ext.seq, 2)
        kinds = [e["kind"] for e in pipe.audit_log()]
        self.assertEqual(kinds, [dp.KIND_REJECTED, dp.KIND_EXTRACTED])

    def test_audit_shapes_and_no_value_leak(self):
        pipe = make_pipe()
        pipe.extract("crm", 1, [{"secret": "hunter2"}])
        pipe.transform("ext-1", 2, [{"op": "select", "fields": ["secret"]}])
        pipe.load("trn-1", 3, "warehouse.x")
        log = pipe.audit_log()
        self.assertEqual(len(log), 3)
        blob = str(log)
        self.assertNotIn("hunter2", blob)
        for event in log:
            self.assertEqual(event["schema"], "audit.ndjson/1")
            self.assertEqual(event["module_version"], "data-pipeline.v1")
        with self.assertRaises(dp.DataPipelineError):
            dp.data_pipeline_audit_event("nope", 9)

    def test_stats_and_views(self):
        pipe = make_pipe()
        pipe.extract("s", 1, [{"a": 1}])
        pipe.transform("ext-1", 2, [{"op": "select", "fields": ["a"]}])
        pipe.load("trn-1", 3, "t")
        stats = pipe.stats()
        self.assertEqual(stats["extracts"], 1)
        self.assertEqual(stats["transforms"], 1)
        self.assertEqual(stats["loads"], 1)
        self.assertEqual(pipe.extract_ids(), ("ext-1",))
        self.assertEqual(pipe.transform_ids(), ("trn-1",))
        self.assertEqual(pipe.load_ids(), ("lod-1",))


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        dp.main()


if __name__ == "__main__":
    unittest.main()
