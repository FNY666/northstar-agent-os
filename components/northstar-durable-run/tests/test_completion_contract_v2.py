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
    SemanticField,
    WorkspaceSnapshot,
)


class CompletionContractV2Tests(unittest.TestCase):
    def provenance(self, **overrides):
        values = {
            "contract_revision": "completion-v2-test-1",
            "evaluator_digest": "sha256:evaluator",
            "fixture_digest": "sha256:fixture",
            "benchmark_commit": "abc123",
            "environment_digest": "sha256:environment",
            "model_id": "fixture/model",
            "model_revision": "model-rev-1",
            "reasoning_effort": "off",
            "max_output_tokens": 2048,
            "seed": "trial-seed-1",
            "trial_id": "trial-1",
        }
        values.update(overrides)
        return Provenance.from_dict(values)

    def snapshot(self, files):
        return WorkspaceSnapshot.from_files(files)

    def contract(self, **overrides):
        values = {
            "required_artifacts": (
                ArtifactExpectation(
                    path="out/report.md",
                    exact_content="# Report\nrows: 4\ntop_scorer: carol\n",
                ),
            ),
            "allowed_mutations": ("out/report.md",),
            "required_milestones": ("read-source", "write-report"),
            "milestone_edges": (("read-source", "write-report"),),
            "expected_provenance": self.provenance(),
        }
        values.update(overrides)
        return CompletionContractV2(**values)

    def test_structured_fields_allow_format_variation_but_reject_negation(self):
        contract = self.contract(
            required_artifacts=(
                ArtifactExpectation(
                    path="out/report.md",
                    semantic_fields=(
                        SemanticField("rows", "4"),
                        SemanticField("top_scorer", "carol"),
                    ),
                ),
            )
        )
        valid = contract.evaluate(
            before=self.snapshot({}),
            after=self.snapshot(
                {"out/report.md": "Rows: 4\nTop Scorer: carol\n"}
            ),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        negated = contract.evaluate(
            before=self.snapshot({}),
            after=self.snapshot(
                {"out/report.md": "Rows: 4\nTop Scorer: NOT carol\n"}
            ),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(valid.verdict, "verified")
        self.assertEqual(negated.verdict, "failed")
        self.assertIn("out/report.md:semantic_field:top_scorer", negated.errors)

    def test_inline_negation_is_rejected_not_just_line_start_negation(self):
        contract = self.contract(
            required_artifacts=(
                ArtifactExpectation(
                    path="out/report.md",
                    semantic_fields=(SemanticField("top_scorer", "carol", mode="contains"),),
                ),
            )
        )
        result = contract.evaluate(
            before=self.snapshot({}),
            after=self.snapshot({"out/report.md": "Top scorer: carol, NOT verified by source\n"}),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("out/report.md:semantic_field:top_scorer", result.errors)

    def test_structured_field_missing_or_digest_only_is_insufficient(self):
        contract = self.contract(
            required_artifacts=(
                ArtifactExpectation(
                    path="out/report.md",
                    semantic_fields=(SemanticField("rows", "4"),),
                ),
            )
        )
        missing = contract.evaluate(
            before=self.snapshot({}),
            after=self.snapshot({"out/report.md": "Top scorer: carol\n"}),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        digest_only = contract.evaluate(
            before=self.snapshot({}),
            after=self.snapshot({"out/report.md": "sha256:" + "a" * 64}),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(missing.verdict, "insufficient_information")
        self.assertEqual(digest_only.verdict, "insufficient_information")


        before = self.snapshot({"README.md": "readme-before"})
        after = self.snapshot(
            {
                "README.md": "readme-before",
                "out/report.md": "# Report\nrows: 4\ntop_scorer: carol\n",
            }
        )
        result = self.contract().evaluate(
            before=before,
            after=after,
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "verified")
        self.assertEqual(result.errors, ())
        self.assertEqual(result.mutation_paths, ("out/report.md",))

    def test_semantic_negation_is_rejected_by_structured_exact_content(self):
        after = self.snapshot(
            {"out/report.md": "# Report\nrows: FALSE\ntop_scorer: NOT VERIFIED\n"}
        )
        result = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("out/report.md:exact_content_mismatch", result.errors)

    def test_unlisted_collateral_file_is_rejected(self):
        after = self.snapshot(
            {
                "out/report.md": "# Report\nrows: 4\ntop_scorer: carol\n",
                "tmp/debug.log": "unexpected",
            }
        )
        result = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("unapproved_mutation:tmp/debug.log", result.errors)

    def test_missing_provenance_is_insufficient_information(self):
        after = self.snapshot(
            {"out/report.md": "# Report\nrows: 4\ntop_scorer: carol\n"}
        )
        result = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("read-source", "write-report"),
            provenance=None,
            run_status="finished",
        )
        self.assertEqual(result.verdict, "insufficient_information")
        self.assertIn("provenance_missing", result.errors)

    def test_missing_milestone_is_insufficient_but_reversed_order_fails(self):
        after = self.snapshot(
            {"out/report.md": "# Report\nrows: 4\ntop_scorer: carol\n"}
        )
        missing = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("write-report",),
            provenance=self.provenance(),
            run_status="finished",
        )
        reversed_order = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("write-report", "read-source"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(missing.verdict, "insufficient_information")
        self.assertEqual(reversed_order.verdict, "failed")
        self.assertIn("milestone_order_invalid", reversed_order.errors)

    def test_provenance_mismatch_fails_and_is_not_unknown(self):
        after = self.snapshot(
            {"out/report.md": "# Report\nrows: 4\ntop_scorer: carol\n"}
        )
        result = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("read-source", "write-report"),
            provenance=self.provenance(model_revision="other-revision"),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("provenance_mismatch:model_revision", result.errors)

    def test_non_finished_run_cannot_verify_even_with_correct_artifact(self):
        after = self.snapshot(
            {"out/report.md": "# Report\nrows: 4\ntop_scorer: carol\n"}
        )
        result = self.contract().evaluate(
            before=self.snapshot({}),
            after=after,
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="paused_unknown",
        )
        self.assertEqual(result.verdict, "unknown")
        self.assertIn("run_not_finished:paused_unknown", result.errors)

    def test_allowed_mutation_change_and_deletion_are_visible(self):
        contract = self.contract(
            required_artifacts=(),
            allowed_mutations=("out/report.md", "out/old.md"),
            required_milestones=(),
            milestone_edges=(),
        )
        result = contract.evaluate(
            before=self.snapshot({"out/old.md": "legacy"}),
            after=self.snapshot({"out/report.md": "new"}),
            milestones=(),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "verified")
        self.assertEqual(result.mutation_paths, ("out/old.md", "out/report.md"))

    def test_allowed_mutation_does_not_make_missing_required_artifact_pass(self):
        result = self.contract().evaluate(
            before=self.snapshot({}),
            after=self.snapshot({"out/other.md": "ready"}),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("out/report.md:missing", result.errors)

    def test_snapshot_rejects_malformed_digest(self):
        with self.assertRaises(ValueError):
            self.snapshot({"artifact.bin": "sha256:not-a-real-digest"})
        with self.assertRaises(ValueError):
            self.snapshot({"artifact.bin": "sha256:" + "g" * 64})

    def test_conflicting_duplicate_semantic_field_is_not_verified(self):
        contract = self.contract(
            required_artifacts=(
                ArtifactExpectation(
                    path="out/report.md",
                    semantic_fields=(SemanticField("rows", "4"),),
                ),
            )
        )
        result = contract.evaluate(
            before=self.snapshot({}),
            after=self.snapshot({"out/report.md": "rows: 4\nrows: 9\n"}),
            milestones=("read-source", "write-report"),
            provenance=self.provenance(),
            run_status="finished",
        )
        self.assertEqual(result.verdict, "failed")
        self.assertIn("out/report.md:semantic_field_conflict:rows", result.errors)

    def test_snapshot_and_contract_reject_escape_paths(self):
        with self.assertRaises(ValueError):
            self.snapshot({"../escape.txt": "sha256:x"})
        with self.assertRaises(ValueError):
            ArtifactExpectation(path="../escape.txt", exact_content="x")
        with self.assertRaises(ValueError):
            CompletionContractV2(
                required_artifacts=(),
                allowed_mutations=("../escape.txt",),
                required_milestones=(),
                milestone_edges=(),
                expected_provenance=self.provenance(),
            )

    def test_semantic_field_rejects_invalid_mode_and_duplicate_names(self):
        with self.assertRaises(ValueError):
            SemanticField("rows", "4", mode="contains_or_exact")
        with self.assertRaises(ValueError):
            ArtifactExpectation(
                path="out/report.md",
                semantic_fields=(
                    SemanticField("rows", "4"),
                    SemanticField("Rows", "4"),
                ),
            )

    def test_digest_expectation_accepts_binary_artifact_without_content_leak(self):
        raw = b"binary\x00artifact"
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.bin"
            path.write_bytes(raw)
            expectation = ArtifactExpectation(path="artifact.bin", exact_digest=digest)
            contract = CompletionContractV2(
                required_artifacts=(expectation,),
                allowed_mutations=("artifact.bin",),
                required_milestones=(),
                milestone_edges=(),
                expected_provenance=self.provenance(),
            )
            result = contract.evaluate(
                before=self.snapshot({}),
                after=self.snapshot({"artifact.bin": digest}),
                milestones=(),
                provenance=self.provenance(),
                run_status="finished",
                workspace_root=path.parent,
            )
        self.assertEqual(result.verdict, "verified")
        self.assertNotIn("binary", json.dumps(result.as_dict()))


if __name__ == "__main__":
    unittest.main()
