#!/usr/bin/env python3
"""Local-only tests for the fail-closed Semgrep normalizer.

All scanner outputs below are in-memory JSON fixtures.  No scanner, candidate
program, network endpoint, credential, or external target is invoked.
"""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from typing import Any

from native_contract import EvidenceError, sha
from semgrep_normalizer import SEMGREP_VERSION, normalize_semgrep


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def wire(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def execution(code: int) -> dict[str, Any]:
    return {
        "status": "completed",
        "started_at": "2026-10-17T12:00:00Z",
        "finished_at": "2026-10-17T12:00:01Z",
        "duration_ms": 1000,
        "exit_code": code,
        "timed_out": False,
        "resource_exhausted": False,
        "output_truncated": False,
    }


def isolation() -> dict[str, Any]:
    return {
        "backend": "bwrap",
        "read_only_inputs": True,
        "network": "denied",
        "credentials": "none",
        "project_code_executed": False,
        "non_root": True,
    }


def template(inputs: dict[str, bytes]) -> dict[str, Any]:
    expected = [
        {"path": path, "sha256": sha(payload), "ecosystems": [], "min_packages": 0}
        for path, payload in sorted(inputs.items())
    ]
    return {
        "schema": "northstar.security-expectation.v1",
        "run_id": "semgrep-unit-001",
        "subject": {
            "start_commit": "a" * 40,
            "patch_sha256": digest("patch"),
            "candidate_manifest_sha256": digest("candidate"),
        },
        "policy": {
            "id": "native-unit-policy",
            "sha256": digest("policy"),
            "blocking_severities": ["high", "critical"],
            "unknown_severity": "review",
            "max_scan_age_seconds": 3600,
            "max_database_age_seconds": 86400,
            "max_clock_skew_seconds": 60,
            "max_duration_ms": 600000,
        },
        "tools": {
            "semgrep": {
                "required": True,
                "not_applicable_reason": None,
                "evidence_file": "semgrep-evidence.json",
                "version": SEMGREP_VERSION,
                "distribution_sha256": digest("semgrep-1.181.0"),
                "normalizer_sha256": digest("normalizer"),
                "config_sha256": digest("config"),
                "rules_sha256": digest("rules"),
                "database_manifest_sha256": None,
                "scan_view_manifest_sha256": digest("semgrep-view"),
                "isolation_backend": "bwrap",
                "expected_inputs": expected,
            },
            "osv-scanner": {
                "required": True,
                "not_applicable_reason": None,
                "evidence_file": "osv-evidence.json",
                "version": "2.7.0",
                "distribution_sha256": digest("osv-2.7.0"),
                "normalizer_sha256": digest("osv-normalizer"),
                "config_sha256": digest("osv-config"),
                "rules_sha256": None,
                "database_manifest_sha256": digest("osv-db"),
                "scan_view_manifest_sha256": digest("osv-view"),
                "isolation_backend": "bwrap",
                "expected_inputs": [
                    {"path": "requirements.txt", "sha256": digest("requirements"), "ecosystems": ["PyPI"], "min_packages": 1}
                ],
            },
        },
    }


def base_stdout(paths: list[str], results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "version": SEMGREP_VERSION,
        "results": [] if results is None else results,
        "errors": [],
        "paths": {"scanned": paths},
        "skipped_rules": [],
        "time": {},
        "engine_kind": "OSS",
    }


def finding(*, path: str = "/input/src/danger.py", fingerprint: str = "fixture-fingerprint",
            raw_severity: str = "INFO", check_id: str = "northstar.fixture.danger") -> dict[str, Any]:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": 7, "col": 1, "offset": 0},
        "end": {"line": 7, "col": 12, "offset": 11},
        "extra": {
            "message": "fixture-only dangerous pattern",
            "metadata": {"severity": "LOW", "untrusted": True},
            "severity": raw_severity,
            "fingerprint": fingerprint,
            "lines": "fixture_call()",
            "is_ignored": False,
            "validation_state": "NO_VALIDATOR",
        },
    }


class SemgrepNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs = {"src/danger.py": b"fixture_call()\n"}
        self.template = template(self.inputs)

    def normalize(self, output: dict[str, Any], *, code: int, severity_map: dict[str, str] | None = None,
                  inputs: dict[str, bytes] | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return normalize_semgrep(
            wire(output),
            template=self.template if context is None else context,
            execution=execution(code),
            isolation=isolation(),
            input_bytes=self.inputs if inputs is None else inputs,
            severity_map={} if severity_map is None else severity_map,
            stderr=b"fixture progress only\n",
        )

    def test_normal_pair_completes_without_findings_and_uses_fixed_artifact_names(self) -> None:
        record = self.normalize(base_stdout(["/input/src/danger.py"]), code=0)
        self.assertEqual(record["coverage"]["status"], "complete")
        self.assertEqual(record["coverage"]["observed_inputs"][0]["path"], "src/danger.py")
        self.assertEqual(record["findings"], [])
        self.assertEqual(record["artifacts"]["stdout"]["name"], "semgrep.stdout.json")
        self.assertEqual(record["artifacts"]["stderr"]["name"], "semgrep.stderr.txt")

    def test_dangerous_pair_preserves_finding_and_trusted_map_overrides_raw_info_and_metadata(self) -> None:
        output = base_stdout(["/input/src/danger.py"], [finding()])
        record = self.normalize(output, code=1, severity_map={"northstar.fixture.danger": "high"})
        self.assertEqual(len(record["findings"]), 1)
        item = record["findings"][0]
        self.assertEqual(item["kind"], "rule")
        self.assertEqual(item["rule_id"], "northstar.fixture.danger")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["location"], {"path": "src/danger.py", "line": 7})
        self.assertEqual(item["message"], "fixture-only dangerous pattern")

    def test_input_bytes_must_match_signed_expected_inputs(self) -> None:
        with self.assertRaises(EvidenceError):
            self.normalize(base_stdout(["/input/src/danger.py"]), code=0, inputs={"src/danger.py": b"changed\n"})

    def test_bad_json_and_duplicate_json_keys_are_rejected(self) -> None:
        for raw in (b"not json", b'{"version":"1.181.0","version":"1.181.0"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(EvidenceError):
                    normalize_semgrep(
                        raw,
                        template=self.template,
                        execution=execution(0),
                        isolation=isolation(),
                        input_bytes=self.inputs,
                        severity_map={},
                    )

    def test_raw_or_template_version_mismatch_is_rejected(self) -> None:
        output = base_stdout(["/input/src/danger.py"])
        output["version"] = "1.180.0"
        with self.assertRaises(EvidenceError):
            self.normalize(output, code=0)
        changed = copy.deepcopy(self.template)
        changed["tools"]["semgrep"]["version"] = "1.180.0"
        with self.assertRaises(EvidenceError):
            self.normalize(base_stdout(["/input/src/danger.py"]), code=0, context=changed)

    def test_errors_skipped_rules_and_skipped_paths_fail_closed(self) -> None:
        cases: list[tuple[str, dict[str, Any]]] = []
        error_output = base_stdout(["/input/src/danger.py"])
        error_output["errors"] = [{"message": "fixture parser issue"}]
        cases.append(("errors", error_output))
        skipped_rule_output = base_stdout(["/input/src/danger.py"])
        skipped_rule_output["skipped_rules"] = [{"check_id": "northstar.fixture.danger"}]
        cases.append(("skipped_rules", skipped_rule_output))
        skipped_path_output = base_stdout(["/input/src/danger.py"])
        skipped_path_output["paths"]["skipped"] = [{"path": "src/danger.py", "reason": "fixture"}]
        cases.append(("skipped_paths", skipped_path_output))
        for name, output in cases:
            with self.subTest(name=name):
                with self.assertRaises(EvidenceError):
                    self.normalize(output, code=0)

    def test_missing_duplicate_or_escaped_scanned_path_is_rejected(self) -> None:
        cases = [
            ("missing", []),
            ("duplicate", ["/input/src/danger.py", "src/danger.py"]),
            ("escape", ["/input/../outside.py"]),
        ]
        for name, paths in cases:
            with self.subTest(name=name):
                with self.assertRaises(EvidenceError):
                    self.normalize(base_stdout(paths), code=0)

    def test_duplicate_finding_and_finding_path_escape_are_rejected(self) -> None:
        duplicate = finding()
        with self.assertRaises(EvidenceError):
            self.normalize(
                base_stdout(["/input/src/danger.py"], [duplicate, copy.deepcopy(duplicate)]),
                code=1,
                severity_map={"northstar.fixture.danger": "high"},
            )
        with self.assertRaises(EvidenceError):
            self.normalize(
                base_stdout(["/input/src/danger.py"], [finding(path="/input/../outside.py")]),
                code=1,
                severity_map={"northstar.fixture.danger": "high"},
            )

    def test_unknown_or_missing_trusted_severity_is_rejected(self) -> None:
        output = base_stdout(["/input/src/danger.py"], [finding(raw_severity="ALIEN")])
        with self.assertRaises(EvidenceError):
            self.normalize(output, code=1, severity_map={"northstar.fixture.danger": "high"})
        output = base_stdout(["/input/src/danger.py"], [finding()])
        with self.assertRaises(EvidenceError):
            self.normalize(output, code=1, severity_map={})
        with self.assertRaises(EvidenceError):
            self.normalize(output, code=1, severity_map={"northstar.fixture.danger": "unknown"})
        with self.assertRaises(EvidenceError):
            self.normalize(output, code=1, severity_map={"northstar.fixture.danger": []})  # type: ignore[dict-item]
        malformed = base_stdout(["/input/src/danger.py"], [finding(raw_severity="INFO")])
        malformed["results"][0]["extra"]["severity"] = []
        with self.assertRaises(EvidenceError):
            self.normalize(malformed, code=1, severity_map={"northstar.fixture.danger": "high"})

    def test_exit_code_findings_contradictions_are_rejected(self) -> None:
        no_findings = base_stdout(["/input/src/danger.py"])
        with self.assertRaises(EvidenceError):
            self.normalize(no_findings, code=1)
        with self.assertRaises(EvidenceError):
            self.normalize(
                base_stdout(["/input/src/danger.py"], [finding()]),
                code=0,
                severity_map={"northstar.fixture.danger": "high"},
            )

    def test_unknown_structure_or_data_controlled_stdout_name_is_rejected(self) -> None:
        unknown = base_stdout(["/input/src/danger.py"])
        unknown["stdout_name"] = "attacker-selected.json"
        with self.assertRaises(EvidenceError):
            self.normalize(unknown, code=0)
        malformed_result = base_stdout(["/input/src/danger.py"], [finding()])
        malformed_result["results"][0]["extra"]["unexpected"] = "not in fixed interface"
        with self.assertRaises(EvidenceError):
            self.normalize(malformed_result, code=1, severity_map={"northstar.fixture.danger": "high"})

    def test_ignored_result_and_noncanonical_paths_structure_are_rejected(self) -> None:
        ignored = base_stdout(["/input/src/danger.py"], [finding()])
        ignored["results"][0]["extra"]["is_ignored"] = True
        with self.assertRaises(EvidenceError):
            self.normalize(ignored, code=1, severity_map={"northstar.fixture.danger": "high"})
        malformed_paths = base_stdout(["/input/src/danger.py"])
        malformed_paths["paths"]["unknown"] = []
        with self.assertRaises(EvidenceError):
            self.normalize(malformed_paths, code=0)


if __name__ == "__main__":
    unittest.main()
