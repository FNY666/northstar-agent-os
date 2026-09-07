"""Transcript -> NDJSON audit feed: mapping, canonical text, CLI export."""
import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import cli
import support  # noqa: F401
from audit_export import (
    AUDIT_SCHEMA_VERSION,
    COMPONENT,
    record_to_audit,
    records_to_ndjson,
    transcript_path_to_ndjson,
)
from sessions import SessionStore


def sample_record(record_type: str, **overrides):
    # Mirrors SessionStore.append: {index, ts, session_id, type, **data}.
    record = {
        "index": 0,
        "ts": "2026-09-07T03:04:05.123Z",
        "session_id": "ns-20260907T030405Z-abcdef01",
        "type": record_type,
    }
    record.update(overrides)
    return record


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class RecordMappingTests(unittest.TestCase):
    def test_session_start_maps_into_the_canonical_envelope(self):
        record = sample_record(
            "session_start",
            data={"provider": "scripted", "mode": "default", "tools": ["Read"]},
        )
        audit = record_to_audit(record)
        self.assertEqual(
            audit,
            {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "component": COMPONENT,
                "event": "session_start",
                "seq": 0,
                "ts": "2026-09-07T03:04:05.123Z",
                "level": "info",
                "payload": {"data": {"provider": "scripted", "mode": "default", "tools": ["Read"]}},
                "session_id": "ns-20260907T030405Z-abcdef01",
            },
        )

    def test_denial_records_are_error_level_and_carry_the_payload(self):
        audit = record_to_audit(
            sample_record(
                "denial", index=4, agent="general", tool="Write",
                source="permission_gate", reason="Write refused by the permission gate",
            )
        )
        self.assertEqual(audit["event"], "denial")
        self.assertEqual(audit["level"], "error")
        self.assertEqual(audit["seq"], 4)
        self.assertEqual(
            audit["payload"],
            {"agent": "general", "tool": "Write", "source": "permission_gate",
             "reason": "Write refused by the permission gate"},
        )

    def test_failed_tool_result_is_error_level_via_content_block(self):
        record = sample_record(
            "tool_result", index=2, agent="general", role="user",
            content=[{"type": "tool_result", "tool_use_id": "call-1", "content": "boom", "is_error": True}],
            is_meta=False,
        )
        self.assertEqual(record_to_audit(record)["level"], "error")

    def test_ok_tool_result_stays_info(self):
        record = sample_record(
            "tool_result", index=3, agent="general",
            content=[{"type": "tool_result", "tool_use_id": "call-2", "content": "ok", "is_error": False}],
            is_meta=False,
        )
        self.assertEqual(record_to_audit(record)["level"], "info")

    def test_signed_action_receipt_record_uses_status_for_audit_level(self):
        denied = record_to_audit(
            sample_record(
                "informational",
                subtype="action_receipt",
                receipt={"status": "denied", "receipt_id": "rcpt-1"},
            )
        )
        completed = record_to_audit(
            sample_record(
                "informational",
                subtype="action_receipt",
                receipt={"status": "completed", "receipt_id": "rcpt-2"},
            )
        )
        self.assertEqual(denied["level"], "error")
        self.assertEqual(completed["level"], "info")

    def test_result_level_follows_the_error_subtype_prefix(self):
        error = record_to_audit(
            sample_record("result", index=9, subtype="error_permission_denied", agent="general")
        )
        self.assertEqual(error["level"], "error")
        ok = record_to_audit(sample_record("result", index=10, subtype="success", agent="general"))
        self.assertEqual(ok["level"], "info")

    def test_top_level_is_error_flag_is_honoured(self):
        audit = record_to_audit(sample_record("informational", index=5, is_error=True, note="x"))
        self.assertEqual(audit["level"], "error")

    def test_envelope_never_repeats_transcript_keys_in_payload(self):
        audit = record_to_audit(
            sample_record("user_prompt", index=1, content=[{"type": "text", "text": "hi"}])
        )
        for key in ("index", "ts", "type", "session_id"):
            self.assertNotIn(key, audit["payload"])

    def test_missing_envelope_keys_raise(self):
        with self.assertRaises(ValueError):
            record_to_audit({"type": "result"})
        with self.assertRaises(ValueError):
            record_to_audit({})


class NdjsonTextTests(unittest.TestCase):
    def test_records_to_ndjson_is_one_canonical_line_per_record(self):
        records = [
            sample_record("session_start", index=0, data={"provider": "scripted"}),
            sample_record("denial", index=4, tool="Write", reason="no"),
            sample_record("result", index=9, subtype="success"),
        ]
        text = records_to_ndjson(records)
        lines = [line for line in text.splitlines() if line]
        self.assertEqual(len(lines), 3)
        parsed = [json.loads(line) for line in lines]
        self.assertEqual([record["event"] for record in parsed], ["session_start", "denial", "result"])
        self.assertEqual([record["level"] for record in parsed], ["info", "error", "info"])

    def test_transcript_file_exports_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory)
            session_id = store.session_id
            store.append("session_start", {"data": {"provider": "scripted"}})
            store.append("tool_result", {"agent": "general", "content": [{"type": "tool_result", "is_error": False, "content": "ok"}], "is_meta": False})
            store.append("denial", {"agent": "general", "tool": "Write", "reason": "read-only"})
            text = transcript_path_to_ndjson(Path(directory) / f"{session_id}.jsonl")
        records = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(
            [record["event"] for record in records],
            ["session_start", "tool_result", "denial"],
        )
        self.assertEqual([record["level"] for record in records], ["info", "info", "error"])
        self.assertEqual(records[2]["seq"], 2)
        self.assertEqual(records[2]["session_id"], session_id)


class CliExportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = SessionStore(directory=self._tmp.name)
        self.session_id = self.store.session_id
        self.store.append("session_start", {"data": {"provider": "scripted"}})
        self.store.append("denial", {"tool": "Edit", "reason": "read-only", "source": "mode"})

    def tearDown(self):
        self._tmp.cleanup()

    def test_sessions_export_emits_canonical_ndjson_to_stdout(self):
        code, out, err = run_cli(
            "sessions", "export", "--session-dir", self._tmp.name, self.session_id
        )
        self.assertEqual(code, 0, err)
        lines = [line for line in out.splitlines() if line]
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["schema_version"], "audit.ndjson/1")
        self.assertEqual(first["component"], COMPONENT)
        self.assertEqual(first["session_id"], self.session_id)
        second = json.loads(lines[1])
        self.assertEqual(second["event"], "denial")
        self.assertEqual(second["level"], "error")

    def test_sessions_export_unknown_session_is_an_error(self):
        code, out, err = run_cli(
            "sessions", "export", "--session-dir", self._tmp.name, "ns-nope"
        )
        self.assertEqual(code, 1)
        self.assertIn("no transcript", err)

    def test_sessions_export_missing_directory_is_an_error(self):
        code, out, err = run_cli(
            "sessions", "export", "--session-dir", "/tmp/does-not-exist-ns", "ns-nope"
        )
        self.assertEqual(code, 1)
        self.assertIn("no transcript", err)


if __name__ == "__main__":
    unittest.main()
