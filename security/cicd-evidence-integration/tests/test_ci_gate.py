"""只用 fixture 验证 CI 身份绑定，不执行真实扫描或发布。"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ci_gate
from security_evidence import evaluate_bundle
from examples.make_fixture import build_fixture


class CIGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
        self.fixture = build_fixture(self.root, now=self.now)
        self.context_path = self.root / "host-expectation.json"
        context = self.fixture["context"]
        self.expected = {
            "host_expectation_sha256": hashlib.sha256(self.context_path.read_bytes()).hexdigest(),
            "run_id": context["run_id"],
            "start_commit": context["subject"]["start_commit"],
            "patch_sha256": context["subject"]["patch_sha256"],
            "candidate_manifest_sha256": context["subject"]["candidate_manifest_sha256"],
            "policy_sha256": context["policy"]["sha256"],
        }
        self.gate = evaluate_bundle(self.root, self.context_path, now=self.now)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pass_requires_all_independent_pins(self) -> None:
        result = ci_gate.bind_gate(self.gate, self.expected)
        self.assertTrue(result["eligible_for_delivery"])
        self.assertTrue(result["ci_binding"]["passed"])
        self.assertEqual(result["exit_code"], 0)

    def test_each_identity_mismatch_fails_closed(self) -> None:
        for key in self.expected:
            with self.subTest(key=key):
                expected = dict(self.expected)
                expected[key] = "wrong-run" if key == "run_id" else "f" * (40 if key == "start_commit" else 64)
                result = ci_gate.bind_gate(self.gate, expected)
                self.assertFalse(result["eligible_for_delivery"])
                self.assertEqual(result["exit_code"], 2)
                self.assertEqual(result["decision"], "invalid")

    def test_missing_expected_pin_fails_closed(self) -> None:
        expected = dict(self.expected)
        del expected["policy_sha256"]
        self.assertEqual(ci_gate.bind_gate(self.gate, expected)["exit_code"], 2)

    def test_trailing_newline_not_accepted_as_digest(self) -> None:
        expected = dict(self.expected)
        expected["host_expectation_sha256"] += "\n"
        self.assertEqual(ci_gate.bind_gate(self.gate, expected)["exit_code"], 2)

    def test_wrong_result_schema_is_invalid(self) -> None:
        gate = copy.deepcopy(self.gate)
        gate["schema"] = "untrusted"
        self.assertEqual(ci_gate.bind_gate(gate, self.expected)["decision"], "invalid")

    def test_known_block_is_preserved(self) -> None:
        gate = copy.deepcopy(self.gate)
        gate.update(decision="block", exit_code=1, eligible_for_delivery=False)
        result = ci_gate.bind_gate(gate, self.expected)
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["exit_code"], 1)
        self.assertFalse(result["eligible_for_delivery"])

    def test_review_is_never_promoted_to_pass(self) -> None:
        gate = copy.deepcopy(self.gate)
        gate.update(decision="review", exit_code=2, eligible_for_delivery=False)
        self.assertEqual(ci_gate.bind_gate(gate, self.expected)["exit_code"], 2)

    def test_invalid_evidence_is_never_promoted(self) -> None:
        gate = copy.deepcopy(self.gate)
        gate.update(decision="invalid", exit_code=2, evidence_valid=False, eligible_for_delivery=False)
        self.assertFalse(ci_gate.bind_gate(gate, self.expected)["eligible_for_delivery"])

    def test_binding_does_not_mutate_original_result(self) -> None:
        original = copy.deepcopy(self.gate)
        ci_gate.bind_gate(self.gate, self.expected)
        self.assertEqual(self.gate, original)

    def test_modified_host_context_cannot_reuse_old_external_pin(self) -> None:
        context = json.loads(self.context_path.read_text())
        context["policy"]["id"] = "attacker-policy"
        self.context_path.write_text(json.dumps(context) + "\n")
        result = evaluate_bundle(self.root, self.context_path, now=self.now)
        bound = ci_gate.bind_gate(result, self.expected)
        self.assertEqual(bound["decision"], "invalid")
        self.assertFalse(bound["ci_binding"]["passed"])

    def test_validator_plus_ci_binding_reads_only(self) -> None:
        before = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        ci_gate.bind_gate(evaluate_bundle(self.root, self.context_path, now=self.now), self.expected)
        after = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_cli_missing_pins_cannot_succeed(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "ci_gate.py"), "--evidence-dir", str(self.root), "--expectation", str(self.context_path)], capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_cli_pass_uses_current_fixture_not_old_saved_result(self) -> None:
        fixture = build_fixture(self.root)
        context = fixture["context"]
        expected = {
            "--expected-expectation-sha256": hashlib.sha256(self.context_path.read_bytes()).hexdigest(),
            "--expected-run-id": context["run_id"],
            "--expected-start-commit": context["subject"]["start_commit"],
            "--expected-patch-sha256": context["subject"]["patch_sha256"],
            "--expected-candidate-manifest-sha256": context["subject"]["candidate_manifest_sha256"],
            "--expected-policy-sha256": context["policy"]["sha256"],
        }
        args = [sys.executable, str(ROOT / "ci_gate.py"), "--evidence-dir", str(self.root), "--expectation", str(self.context_path)]
        for key, value in expected.items():
            args.extend([key, value])
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["ci_binding"]["passed"])


if __name__ == "__main__":
    unittest.main()
