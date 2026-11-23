"""控制面和预签入口的测试；临时keys/扫描记录均非生产证据。"""
import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from bootstrap_identity import build_identity
from issue_plan import issue_plan
from materialize_key import materialize
from produce_expectation import produce_expectation
from producer_fixtures import build_scenario, private_key_pem
from trusted_common import EvidenceError, load_private_key, sha, verify_receipt, wire


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_REPOSITORY": "owner/repository", "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": "a" * 40}

    def test_current_context_and_fresh_nonce(self):
        a, b = build_identity(self.env), build_identity(self.env)
        self.assertEqual(a["source_commit"], self.env["GITHUB_SHA"])
        self.assertEqual(a["run_id"], "gh-12345")
        self.assertEqual(a["run_attempt"], 2)
        self.assertNotEqual(a["nonce"], b["nonce"])

    def test_missing_context_rejected(self):
        for key in self.env:
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                build_identity({k: v for k, v in self.env.items() if k != key})

    def test_malformed_attempt_rejected(self):
        for value in ("true", "1.0", "-1", "0", "１", "1000001"):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                build_identity(dict(self.env, GITHUB_RUN_ATTEMPT=value))

    def test_context_cannot_be_shell_or_path_text(self):
        with self.assertRaises(EvidenceError):
            build_identity(dict(self.env, GITHUB_RUN_ID="$(touch forbidden)"))


class PlanAndProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.s = build_scenario(self.root / "scenario")
        self.body = self.root / "trusted-plan-body.json"
        self.body.write_bytes(wire(self.s.plan_body))

    def tearDown(self):
        self.temp.cleanup()

    def test_issue_preapproved_plan_with_external_role_root(self):
        output = self.root / "pre-scan-plan"
        result = issue_plan(self.body, output, self.s.trust, self.s.identity, self.s.keys["plan"], now=self.s.now)
        raw = (output / "plan.dsse.json").read_bytes()
        self.assertEqual(result["plan_sha256"], sha(raw))
        payload = verify_receipt(raw, self.s.trust, expected_kind="scan-plan", expected_identity=self.s.identity, now=self.s.now)
        self.assertEqual(payload["body"], self.s.plan_body)

    def test_issue_plan_rejects_real_evidence_hash_in_template(self):
        body = copy.deepcopy(self.s.plan_body)
        body["expectation_template"]["tools"]["semgrep"]["evidence_sha256"] = "c" * 64
        self.body.write_bytes(wire(body))
        with self.assertRaises(EvidenceError):
            issue_plan(self.body, self.root / "out", self.s.trust, self.s.identity, self.s.keys["plan"], now=self.s.now)
        self.assertFalse((self.root / "out").exists())

    def test_capture_key_cannot_issue_plan(self):
        with self.assertRaises(EvidenceError):
            issue_plan(self.body, self.root / "out", self.s.trust, self.s.identity, self.s.keys["capture"], now=self.s.now)
        self.assertFalse((self.root / "out").exists())

    def test_start_commit_may_differ_from_final_source_commit(self):
        base = "c" * 40
        self.s.plan_body["expectation_template"]["subject"]["start_commit"] = base
        for tool in self.s.records:
            self.s.records[tool]["subject"]["start_commit"] = base
            self.s.sync_record(tool)
        self.s.write_plan()
        self.s.write_capture()
        result = produce_expectation(self.s.plan_path, self.s.capture_path, self.s.evidence_dir, self.root / "out", self.s.trust, self.s.identity, self.s.keys["expectation"], now=self.s.now)
        self.assertEqual(result["exit_code"], 0)

    def test_producer_gate_name_reserved_for_sealing(self):
        self.s.plan_body["expectation_template"]["tools"]["semgrep"]["evidence_file"] = "producer-gate.json"
        self.s.write_plan()
        self.s.write_capture()
        with self.assertRaises(EvidenceError):
            produce_expectation(self.s.plan_path, self.s.capture_path, self.s.evidence_dir, self.root / "out", self.s.trust, self.s.identity, self.s.keys["expectation"], now=self.s.now)

    def test_plan_output_not_overwritten(self):
        output = self.root / "plan"
        issue_plan(self.body, output, self.s.trust, self.s.identity, self.s.keys["plan"], now=self.s.now)
        old = (output / "plan.dsse.json").read_bytes()
        with self.assertRaises(EvidenceError):
            issue_plan(self.body, output, self.s.trust, self.s.identity, self.s.keys["plan"], now=self.s.now)
        self.assertEqual((output / "plan.dsse.json").read_bytes(), old)

    def test_secret_materialization_is_private_and_not_generated_by_job(self):
        key = self.s.keys["expectation"]
        with patch.dict(os.environ, {"NORTHSTAR_UNIT_KEY": private_key_pem(key).decode()}, clear=False):
            path = materialize("NORTHSTAR_UNIT_KEY", self.root)
            self.assertNotIn("NORTHSTAR_UNIT_KEY", os.environ)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(load_private_key(path).public_key().public_bytes_raw(), key.public_key().public_bytes_raw())

    def test_bad_secret_leaves_no_private_staging(self):
        before = {p.name for p in self.root.iterdir()}
        with patch.dict(os.environ, {"NORTHSTAR_UNIT_KEY": "invalid"}, clear=False), self.assertRaises(EvidenceError):
            materialize("NORTHSTAR_UNIT_KEY", self.root)
        self.assertEqual(before, {p.name for p in self.root.iterdir()})


if __name__ == "__main__":
    unittest.main()
