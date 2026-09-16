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

    def test_recovery_fixture_declares_a_bounded_host_fault(self):
        fixture = json.loads(
            (ROOT / "live" / "shadow" / "02-transient-recovery-shadow.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(fixture["fault"], {"action_id": "workspace.write", "count": 1})
        result = build_contract(fixture["shadow_contract"], provenance()).evaluate(
            before=WorkspaceSnapshot.from_files({"README.md": "seed\n"}),
            after=WorkspaceSnapshot.from_files(
                {
                    "README.md": "seed\n",
                    "out/recovery.md": (
                        "service: atlas\n"
                        "incident: degraded\n"
                        "next_action: restart worker pool\n"
                    ),
                }
            ),
            milestones=("list", "read", "write"),
            provenance=provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "verified")

    def test_real_negation_fixture_preserves_legacy_contains_but_contract_fails(self):
        fixture = json.loads(
            (ROOT / "live" / "shadow" / "03-semantic-negation-shadow.json").read_text(
                encoding="utf-8"
            )
        )
        content = (
            "number_of_data_rows: 4\n"
            "columns: name, score, city\n"
            "top_scorer: carol, NOT verified by source\n"
        )
        self.assertTrue(all(value in content for value in fixture["expect"][0]["contains"]))
        result = build_contract(fixture["shadow_contract"], provenance()).evaluate(
            before=WorkspaceSnapshot.from_files({"README.md": "seed\n"}),
            after=WorkspaceSnapshot.from_files({"README.md": "seed\n", "out/report.md": content}),
            milestones=("list", "read", "write"),
            provenance=provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
    def test_collateral_fixture_is_legacy_acceptable_but_contract_rejects_extra_file(self):
        fixture = json.loads(
            (ROOT / "live" / "shadow" / "04-collateral-mutation-shadow.json").read_text(
                encoding="utf-8"
            )
        )
        report = (
            "number_of_data_rows: 4\n"
            "columns: name, score, city\n"
            "top_scorer: carol\n"
        )
        self.assertTrue(all(value in report for value in fixture["expect"][0]["contains"]))
        result = build_contract(fixture["shadow_contract"], provenance()).evaluate(
            before=WorkspaceSnapshot.from_files({"README.md": "seed\n"}),
            after=WorkspaceSnapshot.from_files(
                {
                    "README.md": "seed\n",
                    "out/report.md": report,
                    "out/notes.txt": "collateral\n",
                }
            ),
            milestones=("list", "read", "write", "write"),
            provenance=provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("out/notes.txt", result.mutation_paths)


if __name__ == "__main__":
    unittest.main()
