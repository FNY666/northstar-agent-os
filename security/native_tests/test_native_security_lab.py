"""固定攻击证据实验室回归测试；不运行真实 scanner、项目代码或构建。"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB_PATH = ROOT / "run-native-security-lab.py"


def _load_lab():
    spec = importlib.util.spec_from_file_location("northstar_native_security_lab", LAB_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - import contract failure
        raise RuntimeError("could not load fixed local attack lab")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


LAB = _load_lab()
EXPECTED_IDS = {
    "scope-laundering",
    "fake-success",
    "replay-nonce",
    "replay-attempt",
    "wheel-swap",
    "old-gate-tamper",
    "new-gate-tamper",
    "context-tamper",
    "source-mismatch",
}


class NativeSecurityLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Run the fixed suite exactly once; every case creates and removes its own temporary fixture.
        cls.result = LAB.run_lab()

    def test_catalog_is_closed_and_contains_required_attack_families(self) -> None:
        catalog = LAB.list_experiments()
        self.assertEqual(EXPECTED_IDS, {item["id"] for item in catalog})
        self.assertEqual(len(catalog), len(EXPECTED_IDS))
        self.assertEqual(set(LAB._ATTACKS), EXPECTED_IDS)

    def test_all_benign_pairs_reach_signed_seal_and_consume_success(self) -> None:
        self.assertTrue(self.result["passed"])
        self.assertEqual(len(EXPECTED_IDS), self.result["summary"]["paired_cases"])
        self.assertEqual(len(EXPECTED_IDS), self.result["summary"]["benign_passed"])
        for case in self.result["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["benign"]["passed"])
                self.assertEqual(0, case["benign"]["seal_exit_code"])
                self.assertEqual(0, case["benign"]["consume_exit_code"])
                self.assertTrue(case["benign"]["eligible_for_publish"])

    def test_every_modified_attack_is_detected_and_blocked_without_key_persistence(self) -> None:
        summary = self.result["summary"]
        self.assertEqual(len(EXPECTED_IDS), summary["attacks_detected"])
        self.assertEqual(len(EXPECTED_IDS), summary["attacks_blocked"])
        self.assertEqual(len(EXPECTED_IDS), summary["mutations_applied"])
        self.assertEqual(6, summary["artifact_mutations_applied"])
        self.assertEqual(3, summary["trusted_context_mutations_applied"])
        self.assertEqual([], summary["failed_cases"])
        for case in self.result["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["attack"]["mutation_applied"])
                self.assertTrue(case["attack"]["detected"])
                self.assertTrue(case["attack"]["blocked"])
                self.assertFalse(case["private_keys_persisted"])

    def test_lab_reports_only_local_fixture_activity(self) -> None:
        self.assertEqual("northstar.native-security-lab.v1", self.result["schema"])
        self.assertTrue(self.result["lab"]["fixture_only"])
        self.assertFalse(self.result["lab"]["real_scanners_executed"])
        self.assertFalse(self.result["lab"]["project_code_executed"])
        self.assertFalse(self.result["lab"]["real_build_executed"])
        self.assertFalse(self.result["lab"]["private_keys_persisted"])
        self.assertFalse(self.result["lab"]["external_targets_accepted"])

    def test_list_mode_creates_no_fixture_and_json_mode_has_no_target_parameter(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, LAB.main(["--list"]))
        listed = json.loads(output.getvalue())
        self.assertEqual(EXPECTED_IDS, {item["id"] for item in listed["experiments"]})
        with self.assertRaises(SystemExit) as rejected:
            LAB.main(["--target", "not-allowed"])
        self.assertEqual(2, rejected.exception.code)


if __name__ == "__main__":
    unittest.main()
