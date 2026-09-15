"""Show the completion contract complements the production gate; it is not a replacement.

A live run writes two separate artifacts. The durable runner writes an event
store consumed by verify_run_completion, while the agent harness writes a hash
chained evidence journal consumed by the completion contract. Neither gate
observes the other's artifact, so this file pins the consequence: each one
accepts a case the other rejects. Production therefore has to compose them, and
swapping one gate for the other would silently drop checks.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
for _path in (COMPONENT_ROOT, COMPONENT_ROOT.parent / "northstar-run-contract"):
    sys.path.insert(0, str(_path))

from completion_contract_v2 import (  # noqa: E402
    ArtifactExpectation,
    CompletionContractV2,
    Provenance,
    SemanticField,
    WorkspaceSnapshot,
)
from durable_contract import EventContract, RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, StepPlan  # noqa: E402
from verifier import verify_run_completion  # noqa: E402

RUN = RunContract.from_dict(
    {
        "schema_version": "northstar.durable-run.v1",
        "task_id": "task-001",
        "thread_id": "thread-001",
        "run_id": "run-001",
        "parent_run_id": None,
        "status": "planned",
        "deadline_at": 2_000,
        "scope_snapshot": ["workspace:read", "workspace:write"],
        "trace_id": "trace-001",
    }
)

ARTIFACT = "out/report.md"
EVIDENCE_KEYS = {
    "event_digest",
    "prev_event_digest",
    "observed_digest",
    "execution_id",
}


def digest_of(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def provenance() -> Provenance:
    return Provenance.from_dict(
        {
            "contract_revision": "composition-1",
            "evaluator_digest": "sha256:" + "a" * 64,
            "fixture_digest": "sha256:" + "b" * 64,
            "benchmark_commit": "0" * 40,
            "environment_digest": "sha256:" + "c" * 64,
            "model_id": "fixture-model",
            "model_revision": "rev-1",
            "reasoning_effort": "off",
            "max_output_tokens": 2048,
            "seed": "seed-1",
            "trial_id": "trial-1",
        }
    )


class GateCompositionTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.store = EventStore(self.root / "events.jsonl")
        self.runner = DurableRunner(
            RUN,
            self.store,
            lease_path=self.root / "run.lease.json",
            lease_ttl_seconds=20,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def complete_run(self):
        """Drive the durable runner to a finished state and return its artifact."""
        target = self.workspace / "out" / "report.md"

        def write_target(_key):
            target.parent.mkdir(mode=0o700)
            target.write_text(
                "Top scorer: carol, NOT verified by source\n", encoding="utf-8"
            )
            return {"claimed": "finished"}

        self.runner.execute(
            [
                StepPlan(
                    step_id="write",
                    input_payload={"file": ARTIFACT},
                    scope_snapshot=["workspace:write"],
                    expected_postconditions=["tests_pass"],
                    action=write_target,
                )
            ],
            owner_id="worker-a",
            now=100,
        )
        return target

    def production_verdict(self, target, *, test_exit_code):
        return verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={ARTIFACT: digest_of(target.read_text(encoding="utf-8"))},
            test_exit_code=test_exit_code,
            now=101,
        )

    def contract_verdict(self, content, *, semantic):
        if semantic:
            expectation = ArtifactExpectation(
                ARTIFACT,
                semantic_fields=(SemanticField("top_scorer", "carol", mode="contains"),),
            )
        else:
            expectation = ArtifactExpectation(
                ARTIFACT, exact_digest=digest_of(content)
            )
        contract = CompletionContractV2(
            required_artifacts=(expectation,),
            allowed_mutations=(ARTIFACT,),
            required_milestones=("write",),
            milestone_edges=(),
            expected_provenance=provenance(),
        )
        return contract.evaluate(
            before=WorkspaceSnapshot.from_files({}),
            after=WorkspaceSnapshot.from_files({ARTIFACT: content}),
            milestones=("write",),
            provenance=provenance(),
            run_status="finished",
        )

    def test_contract_verifies_a_run_the_production_gate_rejects_on_exit_code(self):
        # The contract never reads the test exit code, so it cannot replace the
        # production gate without dropping that check.
        target = self.complete_run()
        content = target.read_text(encoding="utf-8")
        contract_result = self.contract_verdict(content, semantic=False)
        gate_result = self.production_verdict(target, test_exit_code=1)
        self.assertEqual(contract_result.verdict, "verified")
        self.assertEqual(gate_result.verdict, "failed")

    def test_production_gate_accepts_the_negated_claim_the_contract_rejects(self):
        # The gate compares digests only, so it is satisfied by a file whose
        # digest matches even when the claim inside it is negated.
        target = self.complete_run()
        content = target.read_text(encoding="utf-8")
        gate_result = self.production_verdict(target, test_exit_code=0)
        contract_result = self.contract_verdict(content, semantic=True)
        self.assertEqual(gate_result.verdict, "verified")
        self.assertEqual(contract_result.verdict, "failed")

    def test_the_two_gates_consume_different_artifacts(self):
        archive = (
            Path("/var/minis/shared/northstar-live-runs/2026-09-11-action-failure-recovery")
            / "evidence"
            / "round-2.evidence.jsonl"
        )
        event = json.loads(archive.read_text(encoding="utf-8").splitlines()[0])
        self.assertTrue(EVIDENCE_KEYS.issubset(set(event)))
        self.assertNotIn("run_id", event)
        self.assertNotIn("trace_id", event)
        self.assertIn("run_id", EventContract.__dataclass_fields__)
        self.assertIn("payload_digest", EventContract.__dataclass_fields__)
