"""Tests for snapshot_tester (Jest toMatchSnapshot shaped, simulated)."""

import unittest

from snapshot_tester import (
    AUDIT_SCHEMA,
    KIND_MATCHED,
    KIND_RECORDED,
    KIND_REJECTED,
    KIND_UPDATED,
    MAX_DIFF_LINES,
    SNAPSHOT_TESTER_SCHEMA,
    SNAPSHOT_TESTER_VERSION,
    BadValueError,
    DuplicateSnapshotError,
    MatchReport,
    SeqOrderError,
    SnapshotRecord,
    SnapshotTester,
    SnapshotTesterError,
    UnknownSnapshotError,
    snapshot_tester_audit_event,
)


def fresh() -> SnapshotTester:
    return SnapshotTester()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SNAPSHOT_TESTER_VERSION, "snapshot-tester.v1")
        self.assertEqual(SNAPSHOT_TESTER_SCHEMA, "northstar.snapshot-tester.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        st = fresh()
        rec = st.snap("pin", {"a": 1}, 1)
        self.assertEqual(rec.version, SNAPSHOT_TESTER_VERSION)
        self.assertEqual(rec.schema, SNAPSHOT_TESTER_SCHEMA)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            (Path(__file__).resolve().parent.parent / "snapshot_tester.py").read_text()
        )
        allowed = {
            "threading", "dataclasses", "typing", "__future__",
            "hashlib", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestSnap(unittest.TestCase):
    def test_snap_roundtrip(self):
        st = fresh()
        rec = st.snap("help", {"args": ["--json"], "exit": 0}, 1)
        self.assertIsInstance(rec, SnapshotRecord)
        self.assertEqual(rec.snapshot_id, "snap-1")
        self.assertEqual(rec.name, "help")
        self.assertEqual(rec.revision, 1)
        self.assertEqual(rec.seq, 1)
        got = st.snapshot("help")
        self.assertEqual(got, rec)
        self.assertEqual(st.snapshot_count(), 1)
        self.assertEqual(st.snapshot_names(), ("help",))

    def test_snap_duplicate_refused(self):
        st = fresh()
        st.snap("dup", [1, 2], 1)
        with self.assertRaises(DuplicateSnapshotError):
            st.snap("dup", [1, 2], 2)
        # The failed mutation still advanced the ledger: same seq rejected.
        with self.assertRaises(SeqOrderError):
            st.snap("other", [3], 2)

    def test_snap_bad_values_refused(self):
        st = fresh()
        for bad in (float("nan"), float("inf"), 2**53, -2**53, 2.0**53,
                    {"k"}, object()):
            with self.assertRaises(BadValueError, msg=f"{bad!r}"):
                st.snap("bad", bad, 1)
        # bool is not int: pins differ from int 1
        r_bool = st.snap("b", True, 1)
        st2 = fresh()
        r_int = st2.snap("b", 1, 1)
        self.assertNotEqual(r_bool.digest, r_int.digest)

    def test_snap_bad_names_and_seqs(self):
        st = fresh()
        for bad_name in ("", 0, None):
            with self.assertRaises(SnapshotTesterError):
                st.snap(bad_name, {}, 1)
        for bad_seq in (True, -1, "1", 1.0):
            with self.assertRaises(SnapshotTesterError):
                st.snap("x", {}, bad_seq)
        st.snap("x", {}, 1)
        with self.assertRaises(SeqOrderError):
            st.snap("y", {}, 1)


class TestMatch(unittest.TestCase):
    def test_match_pass(self):
        st = fresh()
        st.snap("v", {"a": [1, 2], "b": "x"}, 1)
        rep = st.match("v", {"b": "x", "a": [1, 2]}, 2)
        self.assertIsInstance(rep, MatchReport)
        self.assertTrue(rep.passed)
        self.assertEqual(rep.diff, ())
        self.assertEqual(rep.expected_digest, rep.actual_digest)
        self.assertTrue(rep.digest.startswith("sha256:"))
        self.assertEqual(st.last_match("v"), rep)
        self.assertEqual(len(st.matches("v")), 1)

    def test_match_fail_is_data_with_diff(self):
        st = fresh()
        st.snap("v", {"a": 1, "b": {"c": "x", "d": [1, 2]}}, 1)
        rep = st.match("v", {"a": 1, "b": {"c": "y", "d": [1, 3]}}, 2)
        self.assertFalse(rep.passed)
        self.assertNotEqual(rep.expected_digest, rep.actual_digest)
        joined = "\n".join(rep.diff)
        self.assertIn("b.c", joined)
        self.assertIn("b.d[1]", joined)
        self.assertLessEqual(len(rep.diff), MAX_DIFF_LINES)

    def test_match_unknown_name(self):
        st = fresh()
        with self.assertRaises(UnknownSnapshotError):
            st.match("nope", {}, 1)
        with self.assertRaises(UnknownSnapshotError):
            st.snapshot("nope")
        with self.assertRaises(UnknownSnapshotError):
            st.update("nope", {}, 2)
        with self.assertRaises(UnknownSnapshotError):
            st.last_match("nope")

    def test_digest_determinism_across_instances(self):
        a, b = fresh(), fresh()
        ra = a.snap("v", {"x": [True, None, 2.5]}, 1)
        rb = b.snap("v", {"x": [True, None, 2.5]}, 1)
        self.assertEqual(ra.digest, rb.digest)
        self.assertTrue(ra.verify({"x": [True, None, 2.5]}))
        self.assertFalse(ra.verify({"x": [True, None, 2.6]}))


class TestUpdate(unittest.TestCase):
    def test_update_bumps_revision(self):
        st = fresh()
        rec = st.snap("v", {"a": 1}, 1)
        upd = st.update("v", {"a": 2}, 2)
        self.assertEqual(upd.snapshot_id, rec.snapshot_id)
        self.assertEqual(upd.revision, 2)
        self.assertNotEqual(upd.digest, rec.digest)
        self.assertEqual(st.snapshot("v"), upd)

    def test_match_passes_after_update(self):
        st = fresh()
        st.snap("v", {"a": 1}, 1)
        st.update("v", {"a": 2}, 2)
        rep = st.match("v", {"a": 2}, 3)
        self.assertTrue(rep.passed)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_boundary(self):
        st = fresh()
        rec = st.snap("v", {"a": 1}, 1)
        ev = snapshot_tester_audit_event(KIND_RECORDED, 2, name=rec.name)
        self.assertEqual(ev["kind"], KIND_RECORDED)
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["module"], SNAPSHOT_TESTER_SCHEMA)
        snapshot_tester_audit_event(KIND_MATCHED, 3, name="v", passed=True)
        snapshot_tester_audit_event(KIND_UPDATED, 4, name="v", revision=2)
        snapshot_tester_audit_event(KIND_REJECTED, 5, name="v", reason="dup")
        # Snapshot values must never cross the audit boundary.
        for banned in ("value", "payload", "expected", "actual"):
            with self.assertRaises(SnapshotTesterError):
                snapshot_tester_audit_event(KIND_RECORDED, 6, **{banned: 1})
        with self.assertRaises(SnapshotTesterError):
            snapshot_tester_audit_event("nope", 6)

    def test_thread_safety(self):
        import threading

        st = fresh()
        counter = [0]
        clock = threading.Lock()
        errors: list = []

        def worker(i: int) -> None:
            try:
                # The counter lock covers the whole snap() so claim order
                # equals execution order: seqs stay strictly increasing.
                with clock:
                    counter[0] += 1
                    st.snap(f"t-{i}", {"i": i}, counter[0])
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(st.snapshot_count(), 8)
        for i in range(8):
            rec = st.snapshot(f"t-{i}")
            self.assertTrue(rec.verify({"i": i}))


class TestMain(unittest.TestCase):
    def test_main(self):
        from snapshot_tester import main

        main()


if __name__ == "__main__":
    unittest.main()
