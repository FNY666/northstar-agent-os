"""Tests for changelog."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from changelog import (  # noqa: E402
    CHANGELOG_VERSION,
    SCHEMA_PIN,
    Changelog,
    ChangelogEntry,
    ChangelogError,
    ReplayError,
    ReplayReport,
    TruncationError,
    TruncationRecord,
    VerificationError,
    changelog_audit_event,
)


def _log_with(n: int) -> Changelog:
    log = Changelog()
    for i in range(n):
        log.append("put", f"k{i}", i, i)
    return log


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CHANGELOG_VERSION, "changelog.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.changelog.v1")


class TestAppend(unittest.TestCase):
    def test_positions_dense(self):
        log = Changelog()
        e0 = log.append("put", "k", 1, 0)
        e1 = log.append("delete", "k", None, 1)
        self.assertEqual((e0.pos, e1.pos), (0, 1))
        self.assertEqual(log.head(), 2)
        self.assertEqual(len(log), 2)

    def test_entry_digest_verifies(self):
        log = _log_with(3)
        self.assertTrue(log.verify())
        log.verify_strict()  # must not raise

    def test_frozen_entry(self):
        log = _log_with(1)
        with self.assertRaises(Exception):
            log.entry(0).op = "x"  # type: ignore[misc]

    def test_empty_op_rejected(self):
        with self.assertRaises(ValueError):
            Changelog().append("", "k", 1, 0)

    def test_non_str_op_rejected(self):
        with self.assertRaises(TypeError):
            Changelog().append(123, "k", 1, 0)  # type: ignore[arg-type]

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            Changelog().append("put", "", 1, 0)

    def test_bool_key_rejected(self):
        with self.assertRaises(TypeError):
            Changelog().append("put", True, 1, 0)  # type: ignore[arg-type]

    def test_nan_value_rejected(self):
        with self.assertRaises(ValueError):
            Changelog().append("put", "k", float("nan"), 0)

    def test_huge_integral_float_rejected(self):
        with self.assertRaises(ValueError):
            Changelog().append("put", "k", float(2**60), 0)

    def test_object_value_rejected(self):
        with self.assertRaises(TypeError):
            Changelog().append("put", "k", object(), 0)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            Changelog().append("put", "k", 1, True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            Changelog().append("put", "k", 1, -1)

    def test_failed_append_appends_nothing(self):
        log = Changelog()
        with self.assertRaises(ValueError):
            log.append("put", "k", float("nan"), 0)
        self.assertTrue(log.is_empty())

    def test_bool_value_distinct_from_int(self):
        log = Changelog()
        a = log.append("put", "k", True, 0)
        b = log.append("put", "k", 1, 1)
        self.assertNotEqual(a.digest, b.digest)


class TestViews(unittest.TestCase):
    def test_entry_roundtrip(self):
        log = _log_with(3)
        e = log.entry(1)
        self.assertEqual((e.op, e.key, e.value), ("put", "k1", 1))

    def test_entry_out_of_range(self):
        log = _log_with(2)
        with self.assertRaises(ChangelogError):
            log.entry(2)
        with self.assertRaises(ChangelogError):
            log.entry(99)

    def test_entries_since(self):
        log = _log_with(4)
        got = log.entries_since(2)
        self.assertEqual([e.pos for e in got], [2, 3])

    def test_entries_since_head_is_empty(self):
        log = _log_with(2)
        self.assertEqual(log.entries_since(2), ())

    def test_entries_since_out_of_range(self):
        log = _log_with(2)
        with self.assertRaises(ChangelogError):
            log.entries_since(3)

    def test_as_dict_shape(self):
        log = _log_with(2)
        d = log.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual((d["base_pos"], d["head"], d["retained"]), (0, 2, 2))


class TestReplay(unittest.TestCase):
    def test_replay_without_applier(self):
        log = _log_with(3)
        report = log.replay()
        self.assertIsInstance(report, ReplayReport)
        self.assertEqual(report.entries_applied, 3)
        self.assertEqual((report.start_pos, report.end_pos), (0, 3))
        self.assertTrue(report.result_digest.startswith("sha256:"))

    def test_replay_order_and_results(self):
        log = _log_with(3)
        seen = []
        report = log.replay(1, lambda e: seen.append(e.pos) or e.key)
        self.assertEqual(seen, [1, 2])
        self.assertEqual(report.entries_applied, 2)
        self.assertEqual(report.start_pos, 1)

    def test_replay_digest_deterministic(self):
        a = _log_with(2).replay(0, lambda e: e.op)
        b = _log_with(2).replay(0, lambda e: e.op)
        self.assertEqual(a.result_digest, b.result_digest)

    def test_replay_empty_range(self):
        log = _log_with(2)
        report = log.replay(2, lambda e: "x")
        self.assertEqual(report.entries_applied, 0)

    def test_applier_exception_wrapped(self):
        log = _log_with(2)

        def bad(entry):
            raise RuntimeError("boom")

        with self.assertRaises(ReplayError):
            log.replay(0, bad)

    def test_applier_junk_result_rejected(self):
        log = _log_with(1)
        with self.assertRaises(ReplayError):
            log.replay(0, lambda e: object())

    def test_non_callable_applier_rejected(self):
        with self.assertRaises(TypeError):
            _log_with(1).replay(0, "nope")  # type: ignore[arg-type]

    def test_replay_out_of_range(self):
        with self.assertRaises(ChangelogError):
            _log_with(2).replay(5)


class TestVerify(unittest.TestCase):
    def test_verify_clean(self):
        self.assertTrue(_log_with(5).verify())

    def test_verify_detects_tamper(self):
        log = _log_with(2)
        entry = log.entry(0)
        object.__setattr__(entry, "digest", "sha256:" + "0" * 64)
        self.assertFalse(log.verify())

    def test_verify_strict_raises_with_pos(self):
        log = _log_with(3)
        entry = log.entry(1)
        object.__setattr__(entry, "digest", "sha256:" + "0" * 64)
        with self.assertRaises(VerificationError) as ctx:
            log.verify_strict()
        self.assertEqual(ctx.exception.pos, 1)

    def test_entry_moved_position_fails(self):
        log = _log_with(2)
        entry = log.entry(0)
        with self.assertRaises(ValueError):
            ChangelogEntry(
                pos=9,
                op=entry.op,
                key=entry.key,
                value=entry.value,
                seq=entry.seq,
                digest=entry.digest,
            )


class TestTruncate(unittest.TestCase):
    def test_truncate_moves_base(self):
        log = _log_with(4)
        rec = log.truncate(2, 9)
        self.assertIsInstance(rec, TruncationRecord)
        self.assertEqual(rec.dropped, 2)
        self.assertIsNone(rec.state_digest)
        self.assertEqual(log.base_pos(), 2)
        self.assertEqual(len(log), 2)
        self.assertEqual(log.entry(2).pos, 2)

    def test_truncate_all(self):
        log = _log_with(2)
        log.truncate(2, 0)
        self.assertTrue(log.is_empty())
        self.assertEqual(log.head(), 2)

    def test_truncate_none(self):
        log = _log_with(2)
        rec = log.truncate(0, 0)
        self.assertEqual(rec.dropped, 0)
        self.assertEqual(len(log), 2)

    def test_truncate_out_of_range(self):
        log = _log_with(2)
        with self.assertRaises(TruncationError):
            log.truncate(3, 0)

    def test_truncate_before_base(self):
        log = _log_with(4)
        log.truncate(2, 0)
        with self.assertRaises(TruncationError):
            log.truncate(1, 0)

    def test_record_as_dict(self):
        rec = _log_with(3).truncate(1, 7)
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual((d["base_pos"], d["upto_pos"], d["dropped"]), (0, 1, 1))
        self.assertIsNone(d["state_digest"])


class TestCheckpoint(unittest.TestCase):
    def test_checkpoint_pins_prefix_digest(self):
        log = _log_with(3)
        rec = log.checkpoint(2, lambda e: (e.op, e.key), 4)
        self.assertEqual(rec.dropped, 2)
        self.assertTrue(rec.state_digest.startswith("sha256:"))
        self.assertEqual(log.base_pos(), 2)
        self.assertTrue(log.verify())

    def test_checkpoint_digest_recomputable(self):
        a = _log_with(3).checkpoint(2, lambda e: (e.op, e.key), 1)
        b = _log_with(3).checkpoint(2, lambda e: (e.op, e.key), 2)
        self.assertEqual(a.state_digest, b.state_digest)

    def test_checkpoint_empty_prefix(self):
        log = _log_with(2)
        rec = log.checkpoint(0, lambda e: "x", 1)
        self.assertEqual(rec.dropped, 0)
        self.assertTrue(rec.state_digest.startswith("sha256:"))

    def test_checkpoint_applier_failure(self):
        log = _log_with(2)

        def bad(entry):
            raise RuntimeError("boom")

        with self.assertRaises(ReplayError):
            log.checkpoint(2, bad, 1)
        # Failed checkpoint truncates nothing.
        self.assertEqual(len(log), 2)

    def test_checkpoint_out_of_range(self):
        with self.assertRaises(TruncationError):
            _log_with(2).checkpoint(5, lambda e: "x", 1)

    def test_checkpoint_non_callable_rejected(self):
        with self.assertRaises(TypeError):
            _log_with(1).checkpoint(1, "nope", 1)  # type: ignore[arg-type]


class TestAuditEvent(unittest.TestCase):
    def test_shapes(self):
        for kind in ("appended", "replayed", "truncated", "checkpointed", "rejected"):
            rec = changelog_audit_event(kind, 3, pos=1, count=2)
            self.assertEqual(rec["format"], "audit.ndjson/1")
            self.assertEqual(rec["schema"], SCHEMA_PIN)
            self.assertEqual(rec["kind"], kind)
            self.assertEqual((rec["seq"], rec["pos"], rec["count"]), (3, 1, 2))

    def test_optional_fields_omitted(self):
        rec = changelog_audit_event("appended", 0)
        self.assertNotIn("pos", rec)
        self.assertNotIn("count", rec)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            changelog_audit_event("bogus", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            changelog_audit_event("appended", True)


class TestStdlibOnly(unittest.TestCase):
    def test_no_non_stdlib_imports(self):
        src = Path(__file__).resolve().parent.parent / "changelog.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "hashlib",
            "json",
            "math",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import changelog

        changelog.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
