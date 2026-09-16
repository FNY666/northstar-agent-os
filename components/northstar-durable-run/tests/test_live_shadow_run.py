from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from completion_contract_v2 import Provenance, WorkspaceSnapshot  # noqa: E402
from live_shadow_run import build_contract  # noqa: E402

FIXTURE = ROOT / "live" / "shadow" / "01-column-report-shadow.json"


def provenance() -> Provenance:
    return Provenance.from_dict(
        {
            "contract_revision": "live-shadow-1",
            "evaluator_digest": "sha256:" + "e" * 64,
            "fixture_digest": "sha256:" + "f" * 64,
            "benchmark_commit": "0" * 40,
            "environment_digest": "sha256:" + "n" * 64,
            "model_id": "fixture-model",
            "model_revision": "fixture",
            "reasoning_effort": "off",
            "max_output_tokens": 1024,
            "seed": "fixture",
            "trial_id": "fixture",
        }
    )


class LiveShadowFixtureTest(unittest.TestCase):
    def test_fixture_declares_machine_checkable_contract(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        spec = fixture["shadow_contract"]
        contract = build_contract(spec, provenance())
        result = contract.evaluate(
            before=WorkspaceSnapshot.from_files({"README.md": "seed\n"}),
            after=WorkspaceSnapshot.from_files(
                {
                    "README.md": "seed\n",
                    "out/report.md": (
                        "number_of_data_rows: 4\n"
                        "columns: name, score, city\n"
                        "top_scorer: carol\n"
                    ),
                }
            ),
            milestones=("list", "read", "write"),
            provenance=provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "verified")
        self.assertEqual(spec["milestone_action_map"]["workspace.write"], "write")

    def test_negated_fixture_output_is_rejected(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        contract = build_contract(fixture["shadow_contract"], provenance())
        result = contract.evaluate(
            before=WorkspaceSnapshot.from_files({"README.md": "seed\n"}),
            after=WorkspaceSnapshot.from_files(
                {
                    "README.md": "seed\n",
                    "out/report.md": (
                        "number_of_data_rows: 4\n"
                        "columns: name, score, city\n"
                        "top_scorer: carol, NOT verified by source\n"
                    ),
                }
            ),
            milestones=("list", "read", "write"),
            provenance=provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")


if __name__ == "__main__":
    unittest.main()
