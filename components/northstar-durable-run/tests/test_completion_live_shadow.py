from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT.parent / "northstar-run-contract", ROOT.parent / "northstar-host", Path(__file__).resolve().parent):
    sys.path.insert(0, str(path))

from agent_entry import AgentHarness, ExpectedArtifact, WRITE_ACTION, build_run  # noqa: E402
from completion_contract_v2 import ArtifactExpectation, CompletionContractV2, Provenance, SemanticField  # noqa: E402
from completion_live_shadow import run_live_shadow  # noqa: E402
from planner_adapter import TypedPlannerAdapter  # noqa: E402
from test_agent_entry import ScriptedCaller, plan_value, step_value  # noqa: E402


class LiveShadowTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "README.md").write_text("seed\n", encoding="utf-8")
        self.run = build_run("shadow-001", clock=lambda: 100)
        self.harness = AgentHarness(
            self.run,
            self.workspace,
            self.root / "evidence.jsonl",
            actor_id="actor-shadow-001",
            workspace_id="workspace-shadow-001",
            clock=lambda: 100,
            secrets={"binding": b"b" * 32, "authorization": b"a" * 32, "approval": b"p" * 32},
        )
        self.provenance = Provenance.from_dict(
            {
                "contract_revision": "live-shadow-1",
                "evaluator_digest": "sha256:" + "e" * 64,
                "fixture_digest": "sha256:" + "f" * 64,
                "benchmark_commit": "0" * 40,
                "environment_digest": "sha256:" + "n" * 64,
                "model_id": "scripted-planner",
                "model_revision": "fixture",
                "reasoning_effort": "off",
                "max_output_tokens": 2048,
                "seed": "shadow-seed",
                "trial_id": "shadow-001",
            }
        )
        self.contract = CompletionContractV2(
            required_artifacts=(
                ArtifactExpectation(
                    path="out/report.md",
                    semantic_fields=(SemanticField("rows", "1", mode="contains"),),
                ),
            ),
            allowed_mutations=("out/report.md",),
            required_milestones=("write",),
            milestone_edges=(),
            expected_provenance=self.provenance,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def planner(self):
        step = step_value(
            "write-report",
            WRITE_ACTION,
            {"path": "out/report.md", "content": "rows: 1\n"},
            ["content_matches_payload"],
        )
        return TypedPlannerAdapter(
            ScriptedCaller(
                plan_value(
                    self.run,
                    [step],
                    workspace_id="workspace-shadow-001",
                    actor_id="actor-shadow-001",
                )
            )
        )

    def test_live_shadow_records_both_gates_without_changing_task_outcome(self):
        outcome = run_live_shadow(
            self.harness,
            "Write the report",
            self.planner(),
            contract=self.contract,
            expectations=[ExpectedArtifact("out/report.md", content="rows: 1\n")],
            provenance=self.provenance,
            milestones=None,
            milestone_action_map={WRITE_ACTION: "write"},
        )
        self.assertTrue(outcome.task_outcome.ok)
        self.assertEqual(outcome.production.verdict, "verified")
        self.assertEqual(outcome.contract.verdict, "verified")
        self.assertEqual(outcome.layered.verdict, "verified")
        self.assertFalse(outcome.layered.execution_authorized)
        self.assertTrue(outcome.before.files["README.md"].content == "seed\n")
        self.assertEqual(outcome.after.files["out/report.md"].content, "rows: 1\n")

    def test_nonfinished_task_status_is_not_adapted_as_verified(self):
        from completion_live_shadow import _production_result
        from completion_contract_v2 import WorkspaceSnapshot

        task = SimpleNamespace(
            run_status="paused_unknown",
            verification=SimpleNamespace(
                verdict="verified", checked=("out/report.md",), failures=()
            ),
        )
        result = _production_result(
            task,
            WorkspaceSnapshot.from_files({"out/report.md": "rows: 1\\n"}),
        )
        self.assertEqual(result.verdict, "unknown")
        self.assertEqual(result.errors, ("run is not finished: paused_unknown",))

    def test_live_shadow_does_not_promote_missing_evidence(self):
        outcome = run_live_shadow(
            self.harness,
            "Write the report",
            self.planner(),
            contract=self.contract,
            expectations=[ExpectedArtifact("out/report.md", content="rows: 1\n")],
            provenance=self.provenance,
            milestones=None,
            milestone_action_map={WRITE_ACTION: "write"},
            evidence_path=self.root / "missing-evidence.jsonl",
        )
        self.assertTrue(outcome.task_outcome.ok)
        self.assertEqual(outcome.production.verdict, "verified")
        self.assertEqual(outcome.contract.verdict, "unknown")
        self.assertEqual(outcome.layered.verdict, "unknown")
        self.assertFalse(outcome.layered.execution_authorized)


if __name__ == "__main__":
    unittest.main()
