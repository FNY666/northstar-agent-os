import json
import os
import unittest
from pathlib import Path

import sessions as sessions_module
from sessions import SessionStore, load_records


class SessionStoreWriteTests(unittest.TestCase):
    def test_appends_one_json_line_per_record(self):
        path = Path(self._tmp()) / "s.jsonl"
        store = SessionStore(path)
        store.append({"n": 1, "text": "héllo"})
        store.append({"n": 2})
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["n"], 1)
        self.assertEqual(first["text"], "héllo")
        self.assertEqual(first["session_id"], store.session_id)

    def test_fsync_is_called_on_every_write(self):
        path = Path(self._tmp()) / "s.jsonl"
        store = SessionStore(path)
        calls = []
        original = os.fsync
        try:
            def counting(fd):
                calls.append(fd)
                return original(fd)

            sessions_module.os.fsync = counting
            store.append({"n": 1})
            store.append({"n": 2})
            store.append({"n": 3})
        finally:
            sessions_module.os.fsync = original
        self.assertEqual(len(calls), 3)

    def test_append_only_preserves_existing_lines(self):
        path = Path(self._tmp()) / "s.jsonl"
        store = SessionStore(path)
        store.append({"n": 1})
        before = path.read_text(encoding="utf-8")
        store.append({"n": 2})
        after = path.read_text(encoding="utf-8")
        self.assertTrue(after.startswith(before))

    def _tmp(self):
        import tempfile

        return tempfile.mkdtemp(prefix="nsrt-session-")


class SessionStoreIdTests(unittest.TestCase):
    def test_new_store_generates_a_session_id(self):
        import tempfile

        path = Path(tempfile.mkdtemp()) / "s.jsonl"
        store = SessionStore(path)
        self.assertEqual(len(store.session_id), 32)

    def test_explicit_session_id_is_honoured(self):
        import tempfile

        path = Path(tempfile.mkdtemp()) / "s.jsonl"
        store = SessionStore(path, session_id="fixed-id")
        self.assertEqual(store.session_id, "fixed-id")

    def test_reopening_a_file_resumes_its_session_id(self):
        import tempfile

        directory = tempfile.mkdtemp()
        path = Path(directory) / "s.jsonl"
        first = SessionStore(path)
        first.append({"n": 1})
        second = SessionStore(path)
        self.assertEqual(second.session_id, first.session_id)

    def test_reopen_after_truncation_still_resumes(self):
        import tempfile

        directory = tempfile.mkdtemp()
        path = Path(directory) / "s.jsonl"
        first = SessionStore(path)
        first.append({"n": 1})
        with path.open("a", encoding="utf-8") as fh:
            fh.write('{"n": 2, "trunca')  # truncated tail, no newline
        second = SessionStore(path)
        self.assertEqual(second.session_id, first.session_id)


class TruncatedTailTests(unittest.TestCase):
    def test_truncated_last_line_is_skipped_not_an_error(self):
        # Invariant: a crash mid-write must not make the session unreadable.
        import tempfile

        directory = tempfile.mkdtemp()
        path = Path(directory) / "s.jsonl"
        store = SessionStore(path)
        store.append({"n": 1, "v": "one"})
        store.append({"n": 2, "v": "two"})
        with path.open("a", encoding="utf-8") as fh:
            fh.write('{"n": 3, "v": "trunca')  # no newline, invalid JSON
        records = load_records(path)
        self.assertEqual([r["n"] for r in records], [1, 2])

    def test_empty_file_and_missing_file_load_empty(self):
        import tempfile

        directory = Path(tempfile.mkdtemp())
        (directory / "empty.jsonl").touch()
        self.assertEqual(load_records(directory / "empty.jsonl"), [])
        self.assertEqual(load_records(directory / "absent.jsonl"), [])

    def test_complete_last_line_is_not_dropped(self):
        import tempfile

        directory = Path(tempfile.mkdtemp())
        path = directory / "s.jsonl"
        path.write_text('{"n": 1}\n{"n": 2}\n', encoding="utf-8")
        self.assertEqual([r["n"] for r in load_records(path)], [1, 2])


if __name__ == "__main__":
    unittest.main()
