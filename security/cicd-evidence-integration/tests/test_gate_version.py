"""仅测试发布消费端的 gate 版本约束，不把简化 fixture 当实际扫描。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verify_release_files as verifier


class GateVersionTests(unittest.TestCase):
    def test_unknown_gate_schema_rejected(self) -> None:
        value = {"schema": "other-system.gate.v99", "run_id": "fixture", "decision": "pass", "exit_code": 0, "eligible_for_delivery": True, "evidence_valid": True}
        outcome = verifier._Outcome()
        verifier._validate_gate(value, None, "fixture", outcome)
        self.assertFalse(outcome.finish()["eligible_for_publish"])
        self.assertIn("GATE_SCHEMA_INVALID", outcome.finish()["reason_codes"])

    def test_missing_gate_schema_rejected(self) -> None:
        value = {"run_id": "fixture", "decision": "pass", "exit_code": 0, "eligible_for_delivery": True, "evidence_valid": True}
        outcome = verifier._Outcome()
        verifier._validate_gate(value, None, "fixture", outcome)
        self.assertFalse(outcome.finish()["eligible_for_publish"])


if __name__ == "__main__":
    unittest.main()
