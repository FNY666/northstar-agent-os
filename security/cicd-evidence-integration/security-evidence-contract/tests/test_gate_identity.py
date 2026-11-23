"""门禁输出本身也必须携带候选身份，不能只有一个无上下文的 pass。"""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from examples.make_fixture import build_fixture
from security_evidence import evaluate_bundle


class GateIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 10, 17, 8, 0, 0, tzinfo=timezone.utc)
        self.fixture = build_fixture(self.root, now=self.now)
        self.context_path = self.root / "host-expectation.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_gate_carries_candidate_run_and_policy_identity(self) -> None:
        result = evaluate_bundle(self.root, self.context_path, now=self.now)
        self.assertTrue(result["eligible_for_delivery"])
        context = self.fixture["context"]
        self.assertEqual(result["run_id"], context["run_id"])
        self.assertEqual(result["subject"], context["subject"])
        self.assertEqual(result["policy"], {key: context["policy"][key] for key in ("id", "sha256")})
        self.assertEqual(result["host_expectation_sha256"], hashlib.sha256(self.context_path.read_bytes()).hexdigest())

    def test_gate_carries_trusted_clock_injection_for_audit(self) -> None:
        result = evaluate_bundle(self.root, self.context_path, now=self.now)
        self.assertEqual(result["checked_at"], "2026-10-17T08:00:00.000000Z")

    def test_bad_context_cannot_yield_bound_pass(self) -> None:
        self.context_path.write_bytes(b'{"schema":"forged"}\n')
        result = evaluate_bundle(self.root, self.context_path, now=self.now)
        self.assertEqual(result["decision"], "invalid")
        self.assertFalse(result["eligible_for_delivery"])
        self.assertIsNone(result["run_id"])
        self.assertIsNone(result["host_expectation_sha256"])


if __name__ == "__main__":
    unittest.main()
