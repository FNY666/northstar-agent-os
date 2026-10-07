"""Crash-durability for the audit hash chain: fsync, short-write retry,
corrupt-tail truncation on reopen, and restart continuity.

Honest scope: these tests cover crash-durability (a record acknowledged is
on stable storage; a torn tail is truncated, never trusted), not Byzantine
fault tolerance.
"""
import json
import os
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

import support  # noqa: F401

from audit_chain import (
    DurableAuditWriter,
    _verify_prefix,
    _write_all,
    verify_file,
)


def sample_record(seq, event="test"):
    return {
        "schema_version": "audit.ndjson/1",
        "component": "northstar-agent-runtime",
        "event": event,
        "seq": seq,
        "ts": f"2026-10-07T10:00:{seq:02d}.000Z",
        "level": "info",
    }


class WriteAllTests(unittest.TestCase):
    def test_write_all_handles_short_writes(self):
        """Partial os.write returns are retried until every byte lands."""
        chunks = []

        def fake_write(fd, data):
            # Simulate a short write: only ever write 3 bytes at a time.
            piece = bytes(data[:3])
            chunks.append(piece)
            return len(piece)

        with mock.patch("audit_chain.os.write", side_effect=fake_write):
            _write_all(999, b"hello world")
        self.assertEqual(b"".join(chunks), b"hello world")

    def test_write_all_single_call_when_full(self):
        """A full write needs exactly one os.write call."""
        calls = []

        def fake_write(fd, data):
            calls.append(bytes(data))
            return len(data)

        with mock.patch("audit_chain.os.write", side_effect=fake_write):
            _write_all(999, b"abc")
        self.assertEqual(calls, [b"abc"])

    def test_write_all_zero_return_raises(self):
        """A zero-byte return on a blocking fd is an error, not a spin."""
        with mock.patch("audit_chain.os.write", return_value=0):
            with self.assertRaises(OSError):
                _write_all(999, b"abc")


class FsyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "audit.ndjson"

    def test_fsync_called_on_durable_append(self):
        """durable=True (default) fsyncs after every append."""
        with mock.patch("audit_chain.os.fsync") as mock_fsync:
            with DurableAuditWriter(self.tmp, component="c", session_id="s") as w:
                w.append(sample_record(1))
                w.append(sample_record(2))
        # One fsync per append (flush() not called here).
        self.assertEqual(mock_fsync.call_count, 2)

    def test_non_durable_skips_fsync(self):
        """durable=False skips fsync (performance-testing mode)."""
        with mock.patch("audit_chain.os.fsync") as mock_fsync:
            with DurableAuditWriter(self.tmp, component="c", durable=False) as w:
                w.append(sample_record(1))
                w.append(sample_record(2))
        mock_fsync.assert_not_called()

    def test_per_call_durable_override(self):
        """append(durable=...) overrides the writer default for one call."""
        with mock.patch("audit_chain.os.fsync") as mock_fsync:
            with DurableAuditWriter(self.tmp, component="c", durable=False) as w:
                w.append(sample_record(1), durable=True)   # fsync
                w.append(sample_record(2), durable=False)  # no fsync
                w.append(sample_record(3))                 # writer default: no fsync
        self.assertEqual(mock_fsync.call_count, 1)

    def test_flush_fsyncs(self):
        """flush() is an explicit durable barrier."""
        with mock.patch("audit_chain.os.fsync") as mock_fsync:
            with DurableAuditWriter(self.tmp, component="c", durable=False) as w:
                w.append(sample_record(1))
                w.flush()
        self.assertEqual(mock_fsync.call_count, 1)


class CorruptTailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "audit.ndjson"
        with DurableAuditWriter(self.tmp, component="c", session_id="s") as w:
            for i in (1, 2, 3):
                w.append(sample_record(i))
            self.good_hash = w.prev_hash

    def _reopen(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            writer = DurableAuditWriter(self.tmp, component="c", session_id="s")
        return writer, caught

    def test_invalid_json_tail_truncated(self):
        """A torn tail (invalid JSON) is truncated; a warning is emitted."""
        with open(self.tmp, "ab") as f:
            f.write(b'{"torn": true, broken json\n')
        writer, caught = self._reopen()
        try:
            self.assertEqual(writer.records, 3)
            self.assertEqual(writer.prev_hash, self.good_hash)
            self.assertEqual(len(caught), 1)
            self.assertIn("corrupt tail", str(caught[0].message))
        finally:
            writer.close()
        # The file itself is truncated: the torn bytes are gone.
        result = verify_file(self.tmp)
        self.assertTrue(result.ok)
        self.assertEqual(result.records, 3)

    def test_broken_chain_tail_truncated(self):
        """Valid JSON with a broken chain link is truncated."""
        fake = {"event": "evil", "prev_hash": "00" * 32, "chain_hash": "ff" * 32}
        with open(self.tmp, "ab") as f:
            f.write((json.dumps(fake) + "\n").encode())
        writer, caught = self._reopen()
        try:
            self.assertEqual(writer.records, 3)
            self.assertEqual(writer.prev_hash, self.good_hash)
            self.assertEqual(len(caught), 1)
        finally:
            writer.close()
        result = verify_file(self.tmp)
        self.assertTrue(result.ok)

    def test_tampered_body_tail_truncated(self):
        """A tail record whose body was edited (chain_hash mismatch) is cut."""
        lines = self.tmp.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[-1])
        rec["event"] = "tampered"  # breaks chain_hash, keeps JSON valid
        lines[-1] = json.dumps(rec)
        self.tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        writer, caught = self._reopen()
        try:
            self.assertEqual(writer.records, 2)
            self.assertEqual(len(caught), 1)
        finally:
            writer.close()

    def test_clean_file_no_warning(self):
        """A healthy file reopens silently with no truncation."""
        writer, caught = self._reopen()
        try:
            self.assertEqual(writer.records, 3)
            self.assertEqual(len(caught), 0)
        finally:
            writer.close()


class RestartContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "audit.ndjson"

    def test_reopen_continues_with_correct_prev_hash(self):
        """After reopen, the next record links to the last valid chain_hash."""
        with DurableAuditWriter(self.tmp, component="c", session_id="s") as w:
            r2 = w.append(sample_record(2))
        with DurableAuditWriter(self.tmp, component="c", session_id="s") as w:
            self.assertEqual(w.prev_hash, r2["chain_hash"])
            r3 = w.append(sample_record(3))
            self.assertEqual(r3["prev_hash"], r2["chain_hash"])
        result = verify_file(self.tmp)
        self.assertTrue(result.ok)
        self.assertEqual(result.chained, 2)

    def test_genesis_minted_once(self):
        """The genesis anchor is created on first append and never repeated."""
        with DurableAuditWriter(self.tmp, component="c", session_id="s",
                               run_id="r") as w:
            r1 = w.append(sample_record(1))
            self.assertIn("genesis", r1)
        with DurableAuditWriter(self.tmp, component="c", session_id="s",
                               run_id="r") as w:
            r2 = w.append(sample_record(2))
            self.assertNotIn("genesis", r2)
        lines = self.tmp.read_text(encoding="utf-8").splitlines()
        genesis_count = sum(1 for ln in lines if '"genesis"' in ln)
        self.assertEqual(genesis_count, 1)

    def test_empty_file_starts_fresh(self):
        """Opening a nonexistent file yields an empty writer (no crash)."""
        missing = Path(tempfile.mkdtemp()) / "new.ndjson"
        with DurableAuditWriter(missing, component="c") as w:
            self.assertIsNone(w.prev_hash)
            self.assertEqual(w.records, 0)
            sealed = w.append(sample_record(1))
            self.assertIn("genesis", sealed)
        self.assertTrue(verify_file(missing).ok)

    def test_verify_on_open_false_skips_scan(self):
        """verify_on_open=False trusts the tail without a warning."""
        with DurableAuditWriter(self.tmp, component="c") as w:
            w.append(sample_record(1))
        with open(self.tmp, "ab") as f:
            f.write(b"not json at all\n")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with DurableAuditWriter(self.tmp, component="c",
                                   verify_on_open=False) as w:
                self.assertEqual(len(caught), 0)
                # Tail hash is still recovered from the last parseable line.
                self.assertIsNotNone(w.prev_hash)


class VerifyPrefixTests(unittest.TestCase):
    def test_verify_prefix_reports_truncation_point(self):
        """_verify_prefix returns the byte offset of the last valid line."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.ndjson"
            with DurableAuditWriter(p, component="c") as w:
                w.append(sample_record(1))
                w.append(sample_record(2))
            raw = p.read_bytes()
            with open(p, "ab") as f:
                f.write(b"\x00\x01garbage\n")
            raw_bad = p.read_bytes()
            last_hash, valid_bytes, count, error = _verify_prefix(raw_bad)
            self.assertEqual(valid_bytes, len(raw))
            self.assertEqual(count, 2)
            self.assertNotEqual(error, "")
            self.assertIsNotNone(last_hash)


class LifecycleTests(unittest.TestCase):
    def test_append_after_close_raises(self):
        """Appending to a closed writer is a loud error, not silent loss."""
        tmp = Path(tempfile.mkdtemp()) / "a.ndjson"
        w = DurableAuditWriter(tmp, component="c")
        w.close()
        with self.assertRaises(ValueError):
            w.append(sample_record(1))

    def test_context_manager_closes(self):
        """The context manager closes the fd on exit."""
        tmp = Path(tempfile.mkdtemp()) / "a.ndjson"
        with DurableAuditWriter(tmp, component="c") as w:
            fd = w._fd
        with self.assertRaises(OSError):
            os.fsync(fd)  # closed fd

    def test_non_dict_record_rejected(self):
        """Only dict records can be sealed onto the chain."""
        tmp = Path(tempfile.mkdtemp()) / "a.ndjson"
        with DurableAuditWriter(tmp, component="c") as w:
            with self.assertRaises(TypeError):
                w.append(["not", "a", "dict"])


if __name__ == "__main__":
    unittest.main()
