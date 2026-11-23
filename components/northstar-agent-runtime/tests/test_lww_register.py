"""Targeted tests for the LWW register interface."""

import ast
import math
import unittest
from pathlib import Path

from lww_register import (
    AUDIT_SCHEMA,
    KIND_ASSIGNED,
    KIND_MERGED,
    KIND_REJECTED,
    LWW_REGISTER_SCHEMA,
    LWW_REGISTER_VERSION,
    LWWRegister,
    LWWRegisterError,
    LWWState,
    AssignmentRecord,
    MergeRecord,
    BadMergeError,
    BadNodeError,
    BadRegisterIdError,
    BadTimestampError,
    BadValueError,
    SeqOrderError,
    lww_register_audit_event,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "lww_register.py"


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(LWW_REGISTER_VERSION, "lww-register.v1")
        self.assertEqual(LWW_REGISTER_SCHEMA, "northstar.lww-register.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_kind_vocabulary(self):
        self.assertEqual(
            tuple(sorted([KIND_ASSIGNED, KIND_MERGED, KIND_REJECTED])),
            ("lww.assigned", "lww.merged", "lww.rejected"),
        )

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        stdlib = {
            "hashlib", "threading", "dataclasses", "typing",
            "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], stdlib, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], stdlib,
                              node.module)

    def test_main(self):
        main()


class TestAssign(unittest.TestCase):
    def setUp(self):
        self.r = LWWRegister("r1")

    def test_initial_value_is_none(self):
        self.assertIsNone(self.r.value())
        self.assertEqual(self.r.timestamp(), (-1, ""))

    def test_assign_roundtrip(self):
        rec = self.r.assign("hello", 1, "node-a", 1)
        self.assertIsInstance(rec, AssignmentRecord)
        self.assertTrue(rec.applied)
        self.assertTrue(rec.verify())
        self.assertEqual(self.r.value(), "hello")
        self.assertEqual(self.r.timestamp(), (1, "node-a"))

    def test_value_types(self):
        cases = [("s", 1), (42, 2), (3.5, 3), (True, 4), (None, 5)]
        for i, (v, ts) in enumerate(cases):
            r = LWWRegister(f"t{i}")
            rec = r.assign(v, ts, "n", ts)
            self.assertTrue(rec.applied, v)
            self.assertEqual(r.value(), v)

    def test_bool_is_not_int(self):
        r1, r2 = LWWRegister("b1"), LWWRegister("b2")
        a = r1.assign(True, 1, "n", 1)
        b = r2.assign(1, 1, "n", 1)
        self.assertNotEqual(a.value_digest, b.value_digest)

    def test_stale_write_is_data_not_error(self):
        self.r.assign("first", 5, "node-a", 1)
        rec = self.r.assign("stale", 3, "node-z", 2)  # older ts, fresh ledger seq
        self.assertFalse(rec.applied)
        self.assertTrue(rec.verify())
        self.assertEqual(self.r.value(), "first")

    def test_same_timestamp_loses(self):
        self.r.assign("first", 5, "node-a", 1)
        rec = self.r.assign("second", 5, "node-a", 2)
        self.assertFalse(rec.applied)
        self.assertEqual(self.r.value(), "first")

    def test_tie_break_by_node_id(self):
        self.r.assign("a", 2, "node-a", 1)
        rec = self.r.assign("b", 2, "node-b", 2)  # same ts, greater node
        self.assertTrue(rec.applied)
        self.assertEqual(self.r.value(), "b")

    def test_bad_values(self):
        bad = [
            {"dict": 1}, ["list"], (1, 2),
            float("nan"), float("inf"), float("-inf"),
            2**53, -(2**53), "x" * 65537, object(),
        ]
        seq = 0
        for v in bad:
            seq += 1
            with self.assertRaises(BadValueError, msg=repr(v)[:40]):
                self.r.assign(v, seq, "n", seq)

    def test_bad_node_ids(self):
        seq = 0
        for nid in ["", "   ", 123, None, True, b"n", "n" * 257]:
            seq += 1
            with self.assertRaises(BadNodeError, msg=repr(nid)[:20]):
                self.r.assign("v", seq, nid, seq)

    def test_bad_register_id(self):
        for rid in ["", 123, None, True]:
            with self.assertRaises(BadRegisterIdError):
                LWWRegister(rid)


class TestSeqDiscipline(unittest.TestCase):
    def setUp(self):
        self.r = LWWRegister("r1")

    def test_seq_rewind(self):
        self.r.assign("a", 5, "n", 5)
        with self.assertRaises(SeqOrderError):
            self.r.assign("b", 5, "n", 5)
        with self.assertRaises(SeqOrderError):
            self.r.assign("b", 4, "n", 4)

    def test_bad_ts_seq_shapes(self):
        seq = 100
        for ts in [-1, True, 1.5, "3", None]:
            seq += 1
            with self.assertRaises(BadTimestampError, msg=repr(ts)):
                self.r.assign("v", ts, "n", seq)

    def test_bad_seq_shapes(self):
        for s in [-1, True, False, 1.5, "3", None]:
            with self.assertRaises(SeqOrderError, msg=repr(s)):
                self.r.assign("v", 1, "n", s)

    def test_failed_mutation_consumes_seq(self):
        with self.assertRaises(BadValueError):
            self.r.assign({"nope": 1}, 1, "n", 1)
        with self.assertRaises(SeqOrderError):  # seq 1 was consumed
            self.r.assign("ok", 1, "n", 1)
        rec = self.r.assign("ok", 2, "n", 2)  # fresh seq works
        self.assertTrue(rec.applied)
        rejected = [e for e in self.r.audit_log()
                    if e["kind"] == KIND_REJECTED]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["detail"]["error"], "BadValueError")


class TestMerge(unittest.TestCase):
    def test_merge_adopts_newer(self):
        a = LWWRegister("r1")
        a.assign("old", 1, "node-a", 1)
        b = LWWRegister("r1")
        b.assign("new", 9, "node-b", 1)
        m = a.merge(b, 2)
        self.assertIsInstance(m, MergeRecord)
        self.assertTrue(m.adopted)
        self.assertTrue(m.verify())
        self.assertEqual(a.value(), "new")
        self.assertEqual(a.timestamp(), (9, "node-b"))

    def test_merge_keeps_local_when_newer(self):
        a = LWWRegister("r1")
        a.assign("mine", 9, "node-a", 1)
        b = LWWRegister("r1")
        b.assign("theirs", 1, "node-b", 1)
        m = a.merge(b, 2)
        self.assertFalse(m.adopted)
        self.assertTrue(m.verify())
        self.assertEqual(a.value(), "mine")

    def test_merge_from_genesis_loses(self):
        a = LWWRegister("r1")
        a.assign("mine", 3, "node-a", 1)
        b = LWWRegister("r1")  # never assigned
        m = a.merge(b, 2)
        self.assertFalse(m.adopted)
        self.assertEqual(a.value(), "mine")

    def test_merge_from_snapshot(self):
        a = LWWRegister("r1")
        a.assign("snap", 7, "node-s", 1)
        st = a.state()
        self.assertIsInstance(st, LWWState)
        self.assertTrue(st.verify())
        b = LWWRegister("r1")
        m = b.merge(st, 1)
        self.assertTrue(m.adopted)
        self.assertEqual(b.value(), "snap")

    def test_merge_bad_input(self):
        a = LWWRegister("r1")
        with self.assertRaises(BadMergeError):
            a.merge("not-a-register", 1)
        with self.assertRaises(BadMergeError):
            a.merge(None, 2)

    def test_merge_register_id_mismatch(self):
        a = LWWRegister("r1")
        b = LWWRegister("r2")
        b.assign("x", 9, "node-b", 1)
        with self.assertRaises(BadMergeError):
            a.merge(b, 1)

    def test_merge_converges_both_ways(self):
        a = LWWRegister("r1")
        b = LWWRegister("r1")
        a.assign("from-a", 4, "node-a", 1)
        b.assign("from-b", 4, "node-b", 1)  # tie -> node-b wins
        a.merge(b, 2)
        b.merge(a, 2)
        self.assertEqual(a.value(), "from-b")
        self.assertEqual(b.value(), "from-b")
        self.assertEqual(a.state().value_digest, b.state().value_digest)


class TestAuditAndViews(unittest.TestCase):
    def test_audit_shapes(self):
        r = LWWRegister("r1")
        r.assign("v", 1, "n", 1)
        r.merge(LWWRegister("r1"), 2)
        kinds = [e["kind"] for e in r.audit_log()]
        self.assertEqual(kinds, [KIND_ASSIGNED, KIND_MERGED])
        for e in r.audit_log():
            self.assertEqual(e["schema"], AUDIT_SCHEMA)
            self.assertEqual(e["module"], LWW_REGISTER_VERSION)
            self.assertNotIn("value", e["detail"])

    def test_audit_value_leak_ban(self):
        with self.assertRaises(LWWRegisterError):
            lww_register_audit_event(
                KIND_ASSIGNED, {"value": "secret"}, 1)

    def test_audit_bad_kind(self):
        with self.assertRaises(LWWRegisterError):
            lww_register_audit_event("bogus", {}, 1)

    def test_as_dict_has_no_raw_value(self):
        r = LWWRegister("r1")
        r.assign("secret-value", 1, "n", 1)
        d = r.as_dict()
        self.assertNotIn("secret-value", str(d))
        self.assertEqual(d["value_digest"], r.state().value_digest)
        self.assertEqual(d["schema"], LWW_REGISTER_SCHEMA)

    def test_determinism_across_instances(self):
        def build():
            r = LWWRegister("det")
            r.assign("x", 1, "node-a", 1)
            r.assign("y", 3, "node-b", 2)
            return r
        a, b = build(), build()
        self.assertEqual(a.state().value_digest, b.state().value_digest)
        ra = a.assign("z", 5, "node-c", 3)
        rb = b.assign("z", 5, "node-c", 3)
        self.assertEqual(ra.digest, rb.digest)


if __name__ == "__main__":
    unittest.main()
