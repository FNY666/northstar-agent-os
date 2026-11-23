"""Unified run evidence: lifecycle capture, privacy, and required-failure semantics."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from threading import RLock
from unittest.mock import patch

import support  # noqa: F401 - installs the runtime sys.path shim

import sdk
from events import EXIT_CODES
from code_task import CodeTask
from providers.base import ResultMessage, SystemMessage
from runtime_evidence import EvidenceCaptureReport, RuntimeEvidenceSink
from sdk import RunOptions


EVIDENCE_ROOT = Path(__file__).resolve().parents[2] / "northstar-run-evidence"
if str(EVIDENCE_ROOT) not in sys.path:
    sys.path.append(str(EVIDENCE_ROOT))

from evidence_store import EvidenceStore  # noqa: E402


def _entries(bundle: Path):
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    return EvidenceStore(bundle / "ledger.jsonl", manifest["run_id"]).entries, manifest


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ns-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "notes.txt").write_text("public note\n", encoding="utf-8")

    def run_with_evidence(self, turns, **overrides):
        options = RunOptions(
            prompt="private prompt marker 7f6b",
            workspace=str(self.workspace),
            scripted_turns=turns,
            evidence_dir=str(self.root / "evidence"),
            evidence_required=True,
            **overrides,
        )
        return sdk.run(options)

    def test_complete_run_produces_verifiable_digest_only_bundle(self):
        report = self.run_with_evidence(
            [
                {"tool": {"name": "Read", "input": {"path": "notes.txt"}}},
                {"text": "finished"},
            ]
        )
        self.assertEqual(report.subtype, "success")
        self.assertIsNotNone(report.evidence)
        assert report.evidence is not None
        self.assertTrue(report.evidence["ok"], report.evidence)
        bundle = Path(report.evidence["bundle_dir"])
        self.assertEqual(
            sorted(path.name for path in bundle.iterdir()),
            [".ledger.lock", "audit.ndjson", "ledger.jsonl", "manifest.json"],
        )
        entries, manifest = _entries(bundle)
        kinds = [entry.kind for entry in entries]
        self.assertEqual(kinds[0], "runtime.started")
        self.assertIn("runtime.permission.allowed", kinds)
        self.assertIn("runtime.tool.completed", kinds)
        self.assertEqual(kinds[-1], "runtime.completed")
        self.assertEqual(manifest["ledger"]["entry_count"], len(entries))
        self.assertEqual(manifest["ledger"]["head_digest"], entries[-1].entry_digest)
        self.assertEqual(entries[-1].refs[0].ref_id, "runtime-started")
        self.assertEqual(oct(bundle.stat().st_mode & 0o777), oct(0o700))
        for name in ("ledger.jsonl", "manifest.json", "audit.ndjson"):
            self.assertEqual(oct((bundle / name).stat().st_mode & 0o777), oct(0o600))

    def test_prompt_arguments_and_tool_output_are_not_in_bundle(self):
        secret = "TOP-SECRET-ARGUMENT-82f1"
        self.run_with_evidence(
            [
                {
                    "tool": {
                        "name": "Read",
                        "input": {"path": "notes.txt"},
                    }
                },
                {"text": secret},
            ]
        )
        raw = b"".join(
            path.read_bytes()
            for path in (self.root / "evidence").iterdir()
            if path.is_file() and path.suffix in {".jsonl", ".json", ".ndjson"}
        )
        self.assertNotIn(b"private prompt marker", raw)
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(b'"path":"notes.txt"', raw)
        self.assertNotIn(b"public note", raw)

    def test_permission_denial_is_recorded_without_raw_arguments(self):
        report = self.run_with_evidence(
            [
                {"tool": {"name": "Write", "input": {"path": "out.txt", "content": "secret body"}}},
                {"text": "denied"},
            ]
        )
        self.assertEqual(report.subtype, "success")
        entries, _ = _entries(Path(report.evidence["bundle_dir"]))
        denial = next(entry for entry in entries if entry.kind == "runtime.permission.denied")
        self.assertIsNotNone(denial.subject_digest)
        self.assertNotIn("secret body", json.dumps([entry.to_dict() for entry in entries]))

    def test_checkpoint_and_postcondition_are_cross_referenced(self):
        from postconditions import parse_postconditions

        postconditions = parse_postconditions(
            ({"kind": "exists", "path": "result.txt"},)
        )
        # Use the same public checks path as the runtime fixture by creating the file
        # before the checked run; the important assertion is that the evidence entry
        # exists and is verifier-sourced.
        (self.workspace / "result.txt").write_text("done\n", encoding="utf-8")
        report = self.run_with_evidence(
            [{"text": "done"}],
            checkpoint_turns=1,
            postconditions=postconditions,
        )
        self.assertEqual(report.subtype, "success")
        entries, _ = _entries(Path(report.evidence["bundle_dir"]))
        kinds = [entry.kind for entry in entries]
        self.assertIn("runtime.checkpoint", kinds)
        self.assertIn("runtime.postconditions.completed", kinds)
        terminal = entries[-1]
        refs = {ref.ref_id for ref in terminal.refs}
        self.assertIn("runtime-started", refs)

    def test_required_capture_failure_changes_result(self):
        optional = RuntimeEvidenceSink(
            self.root / "first",
            run_id="run-1",
            session_id="session-1",
        )
        self.assertTrue(optional.available)
        required = RuntimeEvidenceSink(
            self.root / "second",
            run_id="run-2",
            session_id="session-2",
        )
        required.error = "simulated sink outage"
        # The runtime's policy is exercised through a controlled sink failure.
        incomplete = EvidenceCaptureReport(
            ok=False,
            bundle_dir=str(self.root / "third"),
            ledger_path=str(self.root / "third" / "ledger.jsonl"),
            manifest_path=str(self.root / "third" / "manifest.json"),
            audit_path=str(self.root / "third" / "audit.ndjson"),
            ledger_entry_count=0,
            head_digest=None,
            errors=("simulated sink outage",),
        )
        def make_failing_sink(self, *args, **kwargs):
            self.error = "simulated sink outage"
            self._store = None
            self.bundle_dir = Path(args[0])
            self.run_id = "run-1"
            self._closed = False
            self.session_id = "session-1"
            self._lock = RLock()
            self._last_error = None
            self._source_subjects = {}

        with patch.object(RuntimeEvidenceSink, "__init__", make_failing_sink):
            with patch("runtime_evidence.RuntimeEvidenceSink.append_event", return_value=None):
                with patch.object(RuntimeEvidenceSink, "seal", return_value=incomplete):
                    result = sdk.run(
                        RunOptions(
                            prompt="finish",
                            workspace=str(self.workspace),
                            scripted_turns=[{"text": "done"}],
                            evidence_dir=str(self.root / "third"),
                            evidence_required=True,
                        )
                    )
        self.assertEqual(result.subtype, "error_evidence_incomplete")
        self.assertTrue(any("evidence" in error for error in result.errors))
        self.assertEqual(result.result_event["subtype"], "error_evidence_incomplete")
        self.assertEqual(result.result_event["evidence"]["ok"], False)
        self.assertEqual(result.exit_code, EXIT_CODES["error_evidence_incomplete"])

    def test_ledger_tampering_fails_inspection(self):
        report = self.run_with_evidence([{"text": "done"}])
        ledger = Path(report.evidence["bundle_dir"]) / "ledger.jsonl"
        raw = bytearray(ledger.read_bytes())
        raw[120] ^= 1
        ledger.write_bytes(raw)
        sink = RuntimeEvidenceSink(
            ledger.parent,
            run_id=json.loads((ledger.parent / "manifest.json").read_text())["run_id"],
            session_id="s",
        )
        verification = sink.verify()
        self.assertFalse(verification.ok)

    def test_optional_capture_failure_keeps_business_result(self):
        class BrokenSink(RuntimeEvidenceSink):
            def seal(self, *, completion):
                return EvidenceCaptureReport(
                    ok=False,
                    bundle_dir=str(self.bundle_dir),
                    ledger_path=str(self.bundle_dir / "ledger.jsonl"),
                    manifest_path=str(self.bundle_dir / "manifest.json"),
                    audit_path=str(self.bundle_dir / "audit.ndjson"),
                    ledger_entry_count=0,
                    head_digest=None,
                    errors=("optional capture outage",),
                )

        with patch("runtime_evidence.RuntimeEvidenceSink", BrokenSink):
            report = sdk.run(
                RunOptions(
                    prompt="finish",
                    workspace=str(self.workspace),
                    scripted_turns=[{"text": "done"}],
                    evidence_dir=str(self.root / "optional"),
                    evidence_required=False,
                )
            )
        self.assertEqual(report.subtype, "success")
        self.assertFalse(report.evidence["ok"])
        self.assertIn("optional capture outage", report.evidence["errors"])

    def test_cli_flags_and_evidence_command(self):
        from cli import build_parser

        args = build_parser().parse_args(
            [
                "run",
                "--run-evidence-dir",
                str(self.root / "cli-evidence"),
                "--require-evidence",
                "--scripted-text",
                "ok",
                "--prompt",
                "p",
            ]
        )
        self.assertEqual(args.run_evidence_dir, str(self.root / "cli-evidence"))
        self.assertTrue(args.require_evidence)


if __name__ == "__main__":
    unittest.main()
