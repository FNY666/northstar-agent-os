"""Contract tests for the northstar.security-gate.v1 reference validator.

Most mutation tests begin with ``build_fixture``'s valid host-pinned bundle.
``_put_record(..., pin=True)`` intentionally re-pins the changed record *only*
when the test is exercising a semantic rule.  This is test scaffolding, not a
production repair path: mutations without a changed host pin must be invalid.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
for module_path in (str(ROOT), str(EXAMPLES)):
    if module_path not in sys.path:
        sys.path.insert(0, module_path)

from make_fixture import build_fixture  # noqa: E402
from security_evidence import EvidenceError, evaluate_bundle, strict_json_loads  # noqa: E402

UTC = timezone.utc


def wire(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class BundleCase(unittest.TestCase):
    """One fresh, dynamically timestamped bundle per test."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="security-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / "bundle"
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.fixture = build_fixture(self.bundle, now=self.now)
        self.expectation = self.bundle / "host-expectation.json"

    @staticmethod
    def evidence_name(tool: str) -> str:
        return "semgrep-evidence.json" if tool == "semgrep" else "osv-evidence.json"

    def _load(self, name: str) -> dict[str, Any]:
        return json.loads((self.bundle / name).read_text(encoding="utf-8"))

    def _write_json(self, name: str, value: Any) -> bytes:
        payload = wire(value)
        (self.bundle / name).write_bytes(payload)
        return payload

    def context(self) -> dict[str, Any]:
        return self._load("host-expectation.json")

    def record(self, tool: str) -> dict[str, Any]:
        return self._load(self.evidence_name(tool))

    def _put_context(self, context: dict[str, Any]) -> None:
        self._write_json("host-expectation.json", context)

    def _put_record(self, tool: str, record: dict[str, Any], *, pin: bool = True) -> None:
        """Write a record; pin=True is deliberately only semantic-test support."""
        payload = self._write_json(self.evidence_name(tool), record)
        if pin:
            context = self.context()
            context["tools"][tool]["evidence_sha256"] = digest(payload)
            self._put_context(context)

    def _write_raw_record(self, tool: str, payload: bytes) -> None:
        (self.bundle / self.evidence_name(tool)).write_bytes(payload)

    def evaluate(self, *, now: datetime | None = None) -> dict[str, Any]:
        return evaluate_bundle(self.bundle, self.expectation, now=self.now if now is None else now)

    def assert_decision(self, decision: str, exit_code: int | None = None, *, now: datetime | None = None) -> dict[str, Any]:
        result = self.evaluate(now=now)
        self.assertEqual(decision, result["decision"], result)
        if exit_code is not None:
            self.assertEqual(exit_code, result["exit_code"], result)
        return result

    def semgrep_finding(self, severity: str = "low") -> dict[str, Any]:
        return {
            "id": "fixture.semgrep.finding.1",
            "kind": "rule",
            "rule_id": "fixture.rule",
            "advisory_id": None,
            "severity": severity,
            "location": {"path": "src/service.py", "line": 1},
            "package": None,
            "message": "Illustrative normalized finding.",
        }

    def make_host_not_applicable(self, tool: str) -> None:
        """Change both host expectation and record into the exact N/A shape."""
        context = self.context()
        expected = context["tools"][tool]
        expected["required"] = False
        expected["not_applicable_reason"] = "Tool is not required for this host-selected scan scope."
        expected["expected_inputs"] = []
        if tool == "osv-scanner":
            expected["database_manifest_sha256"] = None

        record = self.record(tool)
        record["execution"] = {
            "status": "not_applicable",
            "started_at": None,
            "finished_at": None,
            "duration_ms": 0,
            "exit_code": None,
            "timed_out": False,
            "resource_exhausted": False,
            "output_truncated": False,
        }
        record["coverage"] = {
            "status": "not_applicable",
            "observed_inputs": [],
            "skipped_inputs": [],
            "unresolved_inputs": [],
            "error_count": 0,
        }
        record["findings"] = []
        record["artifacts"] = {"stdout": None, "stderr": None}
        if tool == "osv-scanner":
            record["tool"]["database"] = None
        payload = wire(record)
        context["tools"][tool]["evidence_sha256"] = digest(payload)
        self._put_context(context)
        (self.bundle / self.evidence_name(tool)).write_bytes(payload)

    def run_cli(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "security_evidence.py"),
                "--evidence-dir",
                str(self.bundle),
                "--expectation",
                str(self.expectation),
            ],
            text=True,
            capture_output=True,
            check=False,
        )


class FixtureAndOutcomeTests(BundleCase):
    def test_standard_fixture_passes(self) -> None:
        result = self.assert_decision("pass", 0)
        self.assertTrue(result["evidence_valid"], result)
        self.assertTrue(result["eligible_for_delivery"], result)
        self.assertEqual("northstar.security-gate.v1", result["schema"])

    def test_builder_returns_context_records_and_raw_artifacts(self) -> None:
        self.assertEqual({"context", "records"}, set(self.fixture))
        self.assertEqual({"semgrep", "osv-scanner"}, set(self.fixture["records"]))
        for filename in (
            "host-expectation.json",
            "semgrep-evidence.json",
            "osv-evidence.json",
            "semgrep.stdout.json",
            "semgrep.stderr.txt",
            "osv.stdout.json",
            "osv.stderr.txt",
        ):
            self.assertTrue((self.bundle / filename).is_file(), filename)
        self.assertEqual("completed", self.fixture["records"]["semgrep"]["execution"]["status"])

    def test_completed_exit_one_with_a_low_finding_is_valid_evidence(self) -> None:
        record = self.record("semgrep")
        record["execution"]["exit_code"] = 1
        record["findings"] = [self.semgrep_finding("low")]
        self._put_record("semgrep", record)  # test-only re-pin: exercise semantics.
        result = self.evaluate()
        self.assertTrue(result["evidence_valid"], result)
        self.assertTrue(result["eligible_for_delivery"], result)
        self.assertEqual("pass", result["decision"], result)

    def test_blocking_finding_blocks_delivery(self) -> None:
        record = self.record("semgrep")
        record["findings"] = [self.semgrep_finding("critical")]
        self._put_record("semgrep", record)
        result = self.assert_decision("block", 1)
        self.assertTrue(result["evidence_valid"], result)
        self.assertFalse(result["eligible_for_delivery"], result)

    def test_unknown_severity_requests_review_under_host_policy(self) -> None:
        record = self.record("semgrep")
        record["findings"] = [self.semgrep_finding("unknown")]
        self._put_record("semgrep", record)
        result = self.assert_decision("review", 2)
        self.assertTrue(result["evidence_valid"], result)

    def test_not_applicable_is_allowed_only_when_host_marks_tool_optional(self) -> None:
        self.make_host_not_applicable("osv-scanner")
        result = self.assert_decision("pass", 0)
        self.assertTrue(result["eligible_for_delivery"], result)

    def test_required_tool_cannot_unilaterally_claim_not_applicable(self) -> None:
        self.make_host_not_applicable("semgrep")
        context = self.context()
        context["tools"]["semgrep"]["required"] = True
        context["tools"]["semgrep"]["not_applicable_reason"] = None
        context["tools"]["semgrep"]["expected_inputs"] = [{
            "path": "src/service.py",
            "sha256": self.fixture["records"]["semgrep"]["coverage"]["observed_inputs"][0]["sha256"],
            "ecosystems": [],
            "min_packages": 0,
        }]
        self._put_context(context)
        result = self.assert_decision("invalid", 2)
        self.assertFalse(result["eligible_for_delivery"], result)

    def test_optional_host_shape_with_observed_input_is_invalid(self) -> None:
        self.make_host_not_applicable("semgrep")
        record = self.record("semgrep")
        record["coverage"]["observed_inputs"] = [self.fixture["records"]["semgrep"]["coverage"]["observed_inputs"][0]]
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)


class CoverageBindingTests(BundleCase):
    def test_mandatory_input_omission_requests_review(self) -> None:
        record = self.record("semgrep")
        record["coverage"]["observed_inputs"] = []
        record["coverage"]["status"] = "incomplete"
        self._put_record("semgrep", record)
        result = self.assert_decision("review", 2)
        self.assertFalse(result["eligible_for_delivery"], result)

    def test_duplicate_observed_path_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["coverage"]["observed_inputs"].append(dict(record["coverage"]["observed_inputs"][0]))
        record["coverage"]["status"] = "incomplete"
        self._put_record("semgrep", record)
        # Duplicate paths violate exact host input binding, even if the
        # producer avoids a separate false `complete` coverage assertion.
        self.assert_decision("invalid", 2)

    def test_osv_package_count_below_host_minimum_requests_review(self) -> None:
        record = self.record("osv-scanner")
        record["coverage"]["observed_inputs"][0]["package_count"] = 1
        # This is honest incomplete coverage.  A false `complete` claim is
        # independently covered below and must be invalid.
        record["coverage"]["status"] = "incomplete"
        self._put_record("osv-scanner", record)
        self.assert_decision("review", 2)

    def test_osv_database_must_cover_observed_ecosystem(self) -> None:
        record = self.record("osv-scanner")
        record["tool"]["database"]["ecosystems"] = ["npm"]
        self._put_record("osv-scanner", record)
        self.assert_decision("review", 2)

    def test_forged_complete_coverage_with_skipped_input_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["coverage"]["skipped_inputs"] = [{"path": "src/service.py", "reason": "fixture skip"}]
        # status deliberately remains complete; the self-contradiction is the point.
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_path_traversal_is_structurally_invalid(self) -> None:
        record = self.record("semgrep")
        record["coverage"]["observed_inputs"][0]["path"] = "src/../service.py"
        context = self.context()
        context["tools"]["semgrep"]["expected_inputs"][0]["path"] = "src/../service.py"
        self._put_context(context)
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_control_character_path_is_structurally_invalid(self) -> None:
        record = self.record("semgrep")
        record["coverage"]["observed_inputs"][0]["path"] = "src/evil\u0001.py"
        context = self.context()
        context["tools"]["semgrep"]["expected_inputs"][0]["path"] = "src/evil\u0001.py"
        self._put_context(context)
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)


class TrustedBindingTests(BundleCase):
    def test_changed_record_without_repin_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["findings"] = [self.semgrep_finding("low")]
        self._put_record("semgrep", record, pin=False)
        self.assert_decision("invalid", 2)

    def test_run_id_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["run_id"] = "stale-run-999"
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_old_run_reuse_is_invalid_against_current_host_run_id(self) -> None:
        record = self.record("osv-scanner")
        record["run_id"] = "prior-host-run"
        self._put_record("osv-scanner", record)
        self.assert_decision("invalid", 2)

    def test_patch_hash_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["subject"]["patch_sha256"] = "0" * 64
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_record_tool_name_is_not_trusted(self) -> None:
        record = self.record("semgrep")
        record["tool"]["name"] = "osv-scanner"
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_tool_version_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["tool"]["version"] = "untrusted-version"
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_distribution_hash_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["tool"]["distribution_sha256"] = "a" * 64
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_config_hash_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["tool"]["config_sha256"] = "b" * 64
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_normalizer_hash_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["tool"]["normalizer_sha256"] = "c" * 64
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_scan_view_hash_mismatch_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["subject"]["scan_view_manifest_sha256"] = "d" * 64
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)


class ArtifactAndFilesystemTests(BundleCase):
    def test_modified_raw_artifact_is_invalid(self) -> None:
        (self.bundle / "semgrep.stdout.json").write_bytes(b'{"altered":true}')
        self.assert_decision("invalid", 2)

    def test_missing_raw_artifact_is_invalid(self) -> None:
        (self.bundle / "osv.stderr.txt").unlink()
        self.assert_decision("invalid", 2)

    def test_oversized_raw_artifact_is_invalid_without_unbounded_read(self) -> None:
        (self.bundle / "semgrep.stdout.json").write_bytes(b"{" + b" " * (16 * 1024 * 1024 + 1))
        self.assert_decision("invalid", 2)

    def test_evidence_symlink_is_rejected(self) -> None:
        source = self.bundle / "semgrep-evidence.json"
        replacement = self.bundle / "outside-evidence.json"
        source.replace(replacement)
        source.symlink_to(replacement.name)
        self.assert_decision("invalid", 2)

    def test_hardlinked_evidence_is_rejected(self) -> None:
        os.link(self.bundle / "semgrep-evidence.json", self.bundle / "second-link.json")
        self.assert_decision("invalid", 2)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO support is required")
    def test_fifo_artifact_is_rejected_without_blocking(self) -> None:
        path = self.bundle / "osv.stderr.txt"
        path.unlink()
        os.mkfifo(path)
        self.assert_decision("invalid", 2)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support is required")
    def test_symlinked_evidence_parent_is_rejected(self) -> None:
        real = self.bundle.with_name("real-bundle")
        self.bundle.rename(real)
        self.bundle.symlink_to(real, target_is_directory=True)
        self.expectation = self.bundle / "host-expectation.json"
        self.assert_decision("invalid", 2)

    def test_evaluator_does_not_modify_read_only_bundle_files(self) -> None:
        for path in self.bundle.iterdir():
            path.chmod(0o444)
        # Record after chmod: changing modes above is test setup, not an evaluator mutation.
        before = {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in self.bundle.iterdir()}
        result = self.assert_decision("pass", 0)
        self.assertTrue(result["evidence_valid"])
        after = {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in self.bundle.iterdir()}
        self.assertEqual(before, after)


class StrictJsonAndSchemaTests(BundleCase):
    def test_sha256_with_trailing_newline_is_invalid(self) -> None:
        # Pinning both sides prevents a mere binding mismatch from masking a
        # permissive end-anchor in the hash schema/semantic validator.
        record = self.record("semgrep")
        record["subject"]["patch_sha256"] += "\n"
        context = self.context()
        context["subject"]["patch_sha256"] += "\n"
        self._put_context(context)
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_commit_with_trailing_newline_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["subject"]["start_commit"] += "\n"
        context = self.context()
        context["subject"]["start_commit"] += "\n"
        self._put_context(context)
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_run_id_with_trailing_newline_is_invalid(self) -> None:
        record = self.record("semgrep")
        record["run_id"] += "\n"
        context = self.context()
        context["run_id"] += "\n"
        self._put_context(context)
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_duplicate_ecosystem_is_invalid(self) -> None:
        # Re-pin only to expose duplicate-ecosystem validation rather than
        # testing the separate host evidence-byte pin check.
        record = self.record("osv-scanner")
        record["coverage"]["observed_inputs"][0]["ecosystems"] = ["PyPI", "PyPI"]
        record["tool"]["database"]["ecosystems"] = ["PyPI", "PyPI"]
        context = self.context()
        context["tools"]["osv-scanner"]["expected_inputs"][0]["ecosystems"] = ["PyPI", "PyPI"]
        self._put_context(context)
        self._put_record("osv-scanner", record)
        self.assert_decision("invalid", 2)

    def test_strict_json_loads_rejects_duplicate_object_keys(self) -> None:
        with self.assertRaises(EvidenceError):
            strict_json_loads(b'{"a":1,"a":2}')

    def test_strict_json_loads_rejects_nan_and_infinity(self) -> None:
        for source in (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}', b'{"value":1e999}'):
            with self.subTest(source=source):
                with self.assertRaises(EvidenceError):
                    strict_json_loads(source)

    def test_bad_json_evidence_is_invalid(self) -> None:
        self._write_raw_record("semgrep", b'{"schema":"x",}')
        self.assert_decision("invalid", 2)

    def test_duplicate_key_evidence_is_invalid(self) -> None:
        self._write_raw_record("semgrep", b'{"schema":"a","schema":"b"}')
        self.assert_decision("invalid", 2)

    def test_nan_evidence_is_invalid(self) -> None:
        raw = wire(self.record("semgrep")).replace(b'60000', b'NaN', 1)
        self._write_raw_record("semgrep", raw)
        self.assert_decision("invalid", 2)

    def test_float_cannot_impersonate_integer(self) -> None:
        record = self.record("semgrep")
        record["execution"]["duration_ms"] = 60000.0
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_boolean_cannot_impersonate_integer(self) -> None:
        record = self.record("semgrep")
        record["coverage"]["error_count"] = True
        self._put_record("semgrep", record)
        self.assert_decision("invalid", 2)

    def test_oversized_evidence_json_is_invalid(self) -> None:
        # The validator's 2 MiB envelope must reject before treating content as evidence.
        self._write_raw_record("semgrep", b"{" + b" " * (2 * 1024 * 1024 + 1))
        self.assert_decision("invalid", 2)

    def test_strict_json_depth_limit_is_enforced(self) -> None:
        payload = b"[" * 12 + b"0" + b"]" * 12
        with self.assertRaises(EvidenceError):
            strict_json_loads(payload, max_depth=8)

    def test_strict_json_node_limit_is_enforced(self) -> None:
        with self.assertRaises(EvidenceError):
            strict_json_loads(b"[0,1,2]", max_nodes=3)


class TemporalExecutionAndIsolationTests(BundleCase):
    def test_expired_scan_requests_review(self) -> None:
        self.assert_decision("review", 2, now=self.now + timedelta(seconds=3601))

    def test_expired_osv_database_requests_review(self) -> None:
        record = self.record("osv-scanner")
        record["tool"]["database"]["updated_at"] = (self.now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._put_record("osv-scanner", record)
        self.assert_decision("review", 2)

    def test_future_finished_at_beyond_clock_skew_requests_review(self) -> None:
        record = self.record("semgrep")
        record["execution"]["started_at"] = (self.now + timedelta(seconds=61)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record["execution"]["finished_at"] = (self.now + timedelta(seconds=91)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record["execution"]["duration_ms"] = 30000
        self._put_record("semgrep", record)
        self.assert_decision("review", 2)

    def test_reversed_execution_timestamps_are_invalid(self) -> None:
        record = self.record("semgrep")
        record["execution"]["started_at"] = self.now.strftime("%Y-%m-%dT%H:%M:%SZ")
        record["execution"]["finished_at"] = (self.now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._put_record("semgrep", record)
        # This is an internally contradictory execution record, rather than
        # merely a reviewable incomplete scan.
        self.assert_decision("invalid", 2)

    def test_timeout_requests_review(self) -> None:
        record = self.record("semgrep")
        record["execution"]["status"] = "timed_out"
        record["execution"]["timed_out"] = True
        self._put_record("semgrep", record)
        self.assert_decision("review", 2)

    def test_resource_exhaustion_requests_review(self) -> None:
        record = self.record("semgrep")
        record["execution"]["status"] = "resource_exhausted"
        record["execution"]["resource_exhausted"] = True
        self._put_record("semgrep", record)
        self.assert_decision("review", 2)

    def test_truncated_output_requests_review(self) -> None:
        record = self.record("semgrep")
        record["execution"]["output_truncated"] = True
        self._put_record("semgrep", record)
        self.assert_decision("review", 2)

    def test_unsafe_isolation_metadata_requests_review(self) -> None:
        record = self.record("semgrep")
        record["isolation"]["read_only_inputs"] = False
        self._put_record("semgrep", record)
        self.assert_decision("review", 2)

    def test_process_backend_requests_review(self) -> None:
        record = self.record("semgrep")
        record["isolation"]["backend"] = "process"
        self._put_record("semgrep", record)
        self.assert_decision("review", 2)


class CliExitTests(BundleCase):
    def test_cli_exit_zero_for_pass(self) -> None:
        completed = self.run_cli()
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_cli_exit_one_for_block(self) -> None:
        record = self.record("semgrep")
        record["findings"] = [self.semgrep_finding("high")]
        self._put_record("semgrep", record)
        completed = self.run_cli()
        self.assertEqual(1, completed.returncode, completed.stderr)

    def test_cli_exit_two_for_invalid(self) -> None:
        (self.bundle / "osv.stdout.json").unlink()
        completed = self.run_cli()
        self.assertEqual(2, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
