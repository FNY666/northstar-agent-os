"""Regression tests for trusted expectation production.

All keys and records are ephemeral test fixtures.  The cases deliberately
exercise that candidate records supply only authenticated bytes, never scope,
policy, or tool pins.
"""
from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from produce_expectation import produce_expectation  # noqa: E402
from producer_fixtures import build_scenario, digest, key_id  # noqa: E402
from trusted_common import EvidenceError, sha, strict_json_loads, verify_receipt  # noqa: E402


class ProducerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="producer-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scenario = build_scenario(self.root)
        self.output = self.root / "published"

    def produce(self, *, identity: dict | None = None, now=None, output: Path | None = None) -> dict:
        return produce_expectation(
            self.scenario.plan_path,
            self.scenario.capture_path,
            self.scenario.evidence_dir,
            self.output if output is None else output,
            self.scenario.trust,
            self.scenario.identity if identity is None else identity,
            self.scenario.keys["expectation"],
            now=self.scenario.now if now is None else now,
        )

    def assert_no_output(self) -> None:
        self.assertFalse(self.output.exists(), "invalid evidence must not receive a partial output directory")

    def output_gate(self) -> dict:
        return strict_json_loads((self.output / "security-gate.json").read_bytes())

    def output_expectation(self) -> dict:
        return strict_json_loads((self.output / "host-expectation.json").read_bytes())

    def test_pass_seals_exact_authenticated_capture_and_receipt_pins(self) -> None:
        answer = self.produce()
        self.assertEqual({"exit_code", "expectation_sha256", "gate_sha256", "receipt_sha256", "output_dir", "decision"}, set(answer))
        self.assertEqual((0, "pass"), (answer["exit_code"], answer["decision"]))
        self.assertEqual(self.scenario.files["semgrep-evidence.json"], (self.output / "semgrep-evidence.json").read_bytes())
        self.assertEqual(self.scenario.plan_path.read_bytes(), (self.output / "plan.dsse.json").read_bytes())
        expectation = self.output_expectation()
        self.assertEqual(sha(self.scenario.files["semgrep-evidence.json"]), expectation["tools"]["semgrep"]["evidence_sha256"])
        self.assertEqual(sha(self.scenario.files["osv-evidence.json"]), expectation["tools"]["osv-scanner"]["evidence_sha256"])
        receipt_raw = (self.output / "expectation.dsse.json").read_bytes()
        receipt = verify_receipt(receipt_raw, self.scenario.trust, expected_kind="expectation", expected_identity=self.scenario.identity, now=self.scenario.now)
        self.assertEqual(answer["receipt_sha256"], sha(receipt_raw))
        self.assertEqual(sha((self.output / "host-expectation.json").read_bytes()), receipt["body"]["expectation_sha256"])
        self.assertEqual(sha((self.output / "security-gate.json").read_bytes()), receipt["body"]["gate_sha256"])

    def test_block_is_valid_diagnostic_and_is_signed_not_released(self) -> None:
        record = self.scenario.records["semgrep"]
        record["execution"]["exit_code"] = 1
        record["findings"] = [{
            "id": "test.blocking.finding",
            "kind": "rule",
            "rule_id": "test.rule",
            "advisory_id": None,
            "severity": "critical",
            "location": {"path": "src/service.py", "line": 1},
            "package": None,
            "message": "Test-only finding.",
        }]
        self.scenario.reseal_capture("semgrep")
        answer = self.produce()
        self.assertEqual((1, "block"), (answer["exit_code"], answer["decision"]))
        gate = self.output_gate()
        self.assertTrue(gate["evidence_valid"], gate)
        self.assertFalse(gate["eligible_for_delivery"], gate)

    def test_review_is_valid_diagnostic_and_is_signed_not_released(self) -> None:
        record = self.scenario.records["semgrep"]
        record["execution"]["status"] = "timed_out"
        record["execution"]["timed_out"] = True
        self.scenario.reseal_capture("semgrep")
        answer = self.produce()
        self.assertEqual((2, "review"), (answer["exit_code"], answer["decision"]))
        self.assertTrue(self.output_gate()["evidence_valid"])

    def test_capture_byte_tamper_is_rejected_before_output(self) -> None:
        (self.scenario.evidence_dir / "semgrep-evidence.json").write_bytes(b'{"forged":true}\n')
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_capture_symlink_is_rejected_before_output(self) -> None:
        evidence = self.scenario.evidence_dir / "semgrep-evidence.json"
        replacement = self.scenario.evidence_dir / "outside.json"
        evidence.replace(replacement)
        evidence.symlink_to(replacement.name)
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_capture_extra_file_is_rejected_even_when_signed(self) -> None:
        self.scenario.files["candidate-control.json"] = b"{}\n"
        self.scenario.write_capture()
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_capture_must_include_all_declared_stdout_and_stderr(self) -> None:
        del self.scenario.files["osv.stderr.txt"]
        self.scenario.write_capture()
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_capture_role_is_enforced(self) -> None:
        capture_id = key_id(self.scenario.keys["capture"])
        self.scenario.trust["keys"][capture_id]["kinds"] = ["scan-plan"]
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_revoked_capture_signer_is_rejected(self) -> None:
        capture_id = key_id(self.scenario.keys["capture"])
        self.scenario.trust["keys"][capture_id]["revoked"] = True
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_wrong_nonce_from_external_control_plane_is_rejected(self) -> None:
        identity = copy.deepcopy(self.scenario.identity)
        identity["nonce"] = "c" * 64
        with self.assertRaises(EvidenceError):
            self.produce(identity=identity)
        self.assert_no_output()

    def test_wrong_attempt_and_source_commit_are_rejected(self) -> None:
        for field, value in (("run_attempt", 2), ("source_commit", "c" * 40)):
            with self.subTest(field=field):
                identity = copy.deepcopy(self.scenario.identity)
                identity[field] = value
                with self.assertRaises(EvidenceError):
                    self.produce(identity=identity)
                self.assert_no_output()

    def test_expired_plan_or_capture_receipt_is_rejected(self) -> None:
        with self.assertRaises(EvidenceError):
            self.produce(now=self.scenario.now + timedelta(seconds=1801))
        self.assert_no_output()

    def test_plan_must_predate_actual_scan(self) -> None:
        self.scenario.write_plan(self.scenario.now - timedelta(seconds=80))
        self.scenario.write_capture()
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_capture_cannot_be_issued_materially_before_scan_finishes(self) -> None:
        self.scenario.write_capture(self.scenario.now - timedelta(seconds=91))
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_signed_plan_template_cannot_contain_replacable_evidence_hashes(self) -> None:
        self.scenario.plan_body["expectation_template"]["tools"]["semgrep"]["evidence_sha256"] = "d" * 64
        self.scenario.write_plan()
        self.scenario.write_capture()
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_plan_byte_rewrite_breaks_capture_pin_and_cannot_relax_policy(self) -> None:
        # The plan's policy lives inside signed bytes.  Changing the plan file without a
        # matching new capture pin cannot turn a high finding into a low-risk policy.
        self.scenario.plan_path.write_bytes(self.scenario.plan_path.read_bytes() + b"\n")
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_invalid_record_semantics_are_not_signed(self) -> None:
        self.scenario.records["semgrep"]["tool"]["version"] = "candidate-selected-tool"
        self.scenario.reseal_capture("semgrep")
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assert_no_output()

    def test_output_is_atomic_no_overwrite(self) -> None:
        first = self.produce()
        original = (self.output / "expectation.dsse.json").read_bytes()
        with self.assertRaises(EvidenceError):
            self.produce()
        self.assertEqual(original, (self.output / "expectation.dsse.json").read_bytes())
        self.assertEqual("pass", first["decision"])

    def test_inputs_are_not_modified(self) -> None:
        watched = [self.scenario.plan_path, self.scenario.capture_path, *self.scenario.evidence_dir.iterdir()]
        before = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in watched}
        for path in watched:
            path.chmod(0o400)
        result = self.produce()
        self.assertEqual("pass", result["decision"])
        after = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in watched}
        self.assertEqual({path: (raw, 0o400) for path, (raw, _) in before.items()}, after)

    def test_cli_uses_real_clock_and_machine_readable_stdout(self) -> None:
        trust_path, identity_path = self.scenario.write_cli_inputs()
        output = self.root / "cli-output"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "produce_expectation.py"),
                "--plan", str(self.scenario.plan_path),
                "--capture", str(self.scenario.capture_path),
                "--evidence-dir", str(self.scenario.evidence_dir),
                "--output", str(output),
                "--trust-store", str(trust_path),
                "--identity", str(identity_path),
                "--signing-key-file", str(self.root / "expectation-private.pem"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        answer = json.loads(completed.stdout)
        self.assertEqual((0, "pass"), (answer["exit_code"], answer["decision"]))
        self.assertTrue(output.is_dir())


if __name__ == "__main__":
    unittest.main()
