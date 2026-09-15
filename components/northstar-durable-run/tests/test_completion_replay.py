import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from completion_contract_v2 import (  # noqa: E402
    ArtifactExpectation,
    CompletionContractV2,
    Provenance,
    WorkspaceSnapshot,
)
from completion_replay import replay_task_report  # noqa: E402


ARCHIVE = Path("/var/minis/shared/northstar-live-runs/2026-09-11-multi-task")


class CompletionReplayTests(unittest.TestCase):
    def provenance(self, fixture_path):
        digest = "sha256:" + hashlib.sha256(fixture_path.read_bytes()).hexdigest()
        return Provenance.from_dict(
            {
                "contract_revision": "completion-v2-replay-1",
                "evaluator_digest": "sha256:" + "e" * 64,
                "fixture_digest": digest,
                "benchmark_commit": "acb04df3f1bb21a41e58092c363c3598937dd340",
                "environment_digest": "sha256:" + "n" * 64,
                "model_id": "deepseek/deepseek-v4-flash",
                "model_revision": "archived-replay",
                "reasoning_effort": "off",
                "max_output_tokens": 2048,
                "seed": "replay-seed-1",
                "trial_id": fixture_path.stem,
            }
        )

    def contract(self, artifact_digest, provenance):
        return CompletionContractV2(
            required_artifacts=(
                ArtifactExpectation(path="out/report.md", exact_digest=artifact_digest),
            ),
            allowed_mutations=("out/report.md",),
            required_milestones=("read-source", "write-report"),
            milestone_edges=(("read-source", "write-report"),),
            expected_provenance=provenance,
        )

    def snapshots(self):
        before = WorkspaceSnapshot.from_files({"README.md": "seed"})
        output = (ARCHIVE / "deliverables" / "report.md").read_bytes()
        output_digest = "sha256:" + hashlib.sha256(output).hexdigest()
        after = WorkspaceSnapshot.from_files(
            {"README.md": "seed", "out/report.md": output.decode("utf-8")}
        )
        return before, after, output_digest

    def test_archived_report_without_provenance_is_insufficient_information(self):
        fixture = ARCHIVE / "fixtures" / "01-column-report.json"
        before, after, output_digest = self.snapshots()
        contract = self.contract(output_digest, self.provenance(fixture))
        result = replay_task_report(
            ARCHIVE / "report.json",
            ARCHIVE / "evidence" / "live-column-report-v2" / "round-2.evidence.jsonl",
            task_id="live-column-report-v2",
            contract=contract,
            before=before,
            after=after,
            milestones=("read-source", "write-report"),
        )
        self.assertEqual(result.verdict, "insufficient_information")
        self.assertIn("provenance_missing", result.errors)

    def test_enriched_report_and_independent_evidence_can_verify(self):
        fixture = ARCHIVE / "fixtures" / "01-column-report.json"
        before, after, output_digest = self.snapshots()
        provenance = self.provenance(fixture)
        contract = self.contract(output_digest, provenance)
        original = json.loads((ARCHIVE / "report.json").read_text(encoding="utf-8"))
        enriched = json.loads(json.dumps(original))
        task = next(item for item in enriched["tasks"] if item["task_id"] == "live-column-report-v2")
        task["provenance"] = provenance.as_dict()
        task["milestones"] = ["read-source", "write-report"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(enriched), encoding="utf-8")
            result = replay_task_report(
                path,
                ARCHIVE / "evidence" / "live-column-report-v2" / "round-2.evidence.jsonl",
                task_id="live-column-report-v2",
                contract=contract,
                before=before,
                after=after,
                milestones=("read-source", "write-report"),
            )
        self.assertEqual(result.verdict, "verified")
        self.assertEqual(result.errors, ())

    def test_malformed_provenance_is_insufficient_not_success(self):
        fixture = ARCHIVE / "fixtures" / "01-column-report.json"
        before, after, output_digest = self.snapshots()
        contract = self.contract(output_digest, self.provenance(fixture))
        report = {
            "tasks": [
                {
                    "task_id": "live-column-report-v2",
                    "provenance": {"model_id": "untrusted"},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            result = replay_task_report(
                path,
                ARCHIVE / "evidence" / "live-column-report-v2" / "round-2.evidence.jsonl",
                task_id="live-column-report-v2",
                contract=contract,
                before=before,
                after=after,
                milestones=("read-source", "write-report"),
            )
        self.assertEqual(result.verdict, "insufficient_information")
        self.assertIn("provenance_invalid", result.errors)


if __name__ == "__main__":
    unittest.main()
