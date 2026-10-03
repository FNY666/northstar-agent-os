"""Transcript -> NDJSON audit feed: mapping, canonical text, CLI export."""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import cli
import support  # noqa: F401

# Test-only parity check against the normative envelope validator. The runtime
# itself stays dependency-free; only this test imports the contract.
_CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "northstar-run-contract"
if str(_CONTRACT_ROOT) not in sys.path:
    sys.path.insert(0, str(_CONTRACT_ROOT))
import audit as normative_audit  # noqa: E402

from audit_export import (
    AUDIT_SCHEMA_VERSION,
    COMPONENT,
    build_provenance,
    record_to_audit,
    records_to_ndjson,
    session_path,
    transcript_path_to_ndjson,
    validate_audit_record,
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


class EnvelopeValidationTests(unittest.TestCase):
    def test_non_canonical_timestamps_are_rejected(self):
        for ts in (
            "2026-09-07T03:04:05.123456Z",  # microsecond precision
            "2026-09-07T03:04:05.12Z",  # wrong fractional width
            "2026-09-07T03:04:05+00:00",  # offset instead of Z
            "2026-09-07 03:04:05",  # not RFC 3339 at all
        ):
            with self.subTest(ts=ts):
                with self.assertRaises(ValueError):
                    record_to_audit(sample_record("assistant", ts=ts))

    def test_second_precision_timestamps_are_accepted(self):
        audit = record_to_audit(sample_record("assistant", ts="2026-09-07T03:04:05Z"))
        self.assertEqual(audit["ts"], "2026-09-07T03:04:05Z")

    def test_non_integer_or_negative_seq_is_rejected(self):
        for index in (-1, True, "3", 3.0):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    record_to_audit(sample_record("assistant", index=index))

    def test_invalid_event_identifier_is_rejected(self):
        with self.assertRaises(ValueError):
            record_to_audit(sample_record("weird type"))

    def test_overlong_session_id_is_rejected(self):
        with self.assertRaises(ValueError):
            record_to_audit(sample_record("assistant", session_id="s" * 201))


class NormativeParityTests(unittest.TestCase):
    """The mirror must agree with northstar-run-contract/audit.py exactly."""

    def test_mirror_output_passes_both_validators(self):
        records = [
            sample_record("session_start", data={"provider": "scripted"}),
            sample_record("denial", index=4, tool="Write", reason="no"),
            sample_record("tool_result", index=7, content=[{"is_error": True}]),
            sample_record("result", index=9, subtype="error_timeout"),
            sample_record("assistant", index=12, ts="2026-09-07T03:04:05Z"),
        ]
        for record in records:
            mirror_out = record_to_audit(record)
            with self.subTest(event=record["type"]):
                self.assertEqual(validate_audit_record(mirror_out), ())
                self.assertEqual(normative_audit.validate_record(mirror_out), ())

    def test_canonical_lines_are_byte_identical(self):
        records = [sample_record("assistant", index=i) for i in range(5)]
        mirror_text = records_to_ndjson(records)
        normative_text = normative_audit.to_ndjson(record_to_audit(r) for r in records)
        self.assertEqual(mirror_text, normative_text)

    def test_both_validators_reject_the_same_bad_records(self):
        bad = [
            sample_record("assistant", ts="2026-09-07T03:04:05.123456Z"),
            sample_record("assistant", index=-1),
            sample_record("weird type"),
        ]
        for record in bad:
            with self.subTest(record=record["type"]):
                with self.assertRaises(ValueError):
                    record_to_audit(record)


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

    def test_session_path_rejects_path_traversal_ids(self):
        with self.assertRaises(ValueError):
            session_path(Path("/tmp/sessions"), "../outside")


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


class ProvenanceBuilderTests(unittest.TestCase):
    """SLSA v1.0-style evidence: build, validate, and mirror parity."""

    def test_builder_emits_explicit_trust_marking_by_default(self):
        prov = build_provenance(
            invocation_id="run-1",
            external_parameters={"tool": "Write", "args": {"path": "/tmp/x"}},
            resolved_dependencies=[{"uri": "tool://Write", "digest": {"sha256": "ab" * 32}}],
        )
        # The default is an *explicit* "untrusted", never an implicit one.
        self.assertEqual(prov["externalParametersTrust"], "untrusted")
        self.assertEqual(prov["buildType"], "https://northstar.dev/agent-run/v1")
        self.assertEqual(prov["builder"]["id"], "https://northstar.dev/runtime/northstar-agent-runtime")
        self.assertEqual(prov["invocationId"], "run-1")
        self.assertTrue(prov["selfAsserted"])

    def test_builder_verified_trust(self):
        prov = build_provenance(
            external_parameters={"q": "checked"},
            external_parameters_trust="verified",
            internal_parameters={"approval_tier": 3},
        )
        self.assertEqual(prov["externalParametersTrust"], "verified")

    def test_builder_rejects_bad_trust_value(self):
        with self.assertRaises(ValueError):
            build_provenance(external_parameters_trust="probably-fine")

    def test_provenance_attaches_to_audit_records_and_passes_both_validators(self):
        record = sample_record("tool_call", index=2, tool="Write")
        audit = record_to_audit(record)
        audit["run_id"] = "run-7"
        audit["provenance"] = build_provenance(
            invocation_id="run-7",
            external_parameters={"tool": "Write"},
        )
        self.assertEqual(validate_audit_record(audit), ())
        self.assertEqual(normative_audit.validate_record(audit), ())

    def test_mirror_and_normative_agree_on_bad_provenance(self):
        # Both validators must reject unmarked external input identically.
        audit = record_to_audit(sample_record("tool_call", index=2))
        bad = build_provenance(external_parameters={"tool": "Write"})
        del bad["externalParametersTrust"]
        audit["provenance"] = bad
        mirror_errors = validate_audit_record(audit)
        normative_errors = normative_audit.validate_record(audit)
        self.assertTrue(any("externalParametersTrust" in e for e in mirror_errors))
        self.assertEqual(mirror_errors, normative_errors)

    def test_mirror_and_normative_agree_on_invocation_mismatch(self):
        audit = record_to_audit(sample_record("tool_call", index=2))
        audit["run_id"] = "run-7"
        audit["provenance"] = build_provenance(invocation_id="run-OTHER")
        mirror_errors = validate_audit_record(audit)
        normative_errors = normative_audit.validate_record(audit)
        self.assertTrue(any("does not match" in e for e in mirror_errors))
        self.assertEqual(mirror_errors, normative_errors)


if __name__ == "__main__":
    unittest.main()
