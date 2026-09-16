"""Run one real-model AgentHarness task with non-authorizing shadow gates."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

from agent_entry import AgentHarness, ExpectedArtifact, build_run
from completion_contract_v2 import ArtifactExpectation, CompletionContractV2, Provenance, SemanticField
from completion_live_shadow import run_live_shadow
from openai_compatible_planner import OpenAICompatiblePlannerCaller, OpenAICompatiblePlannerConfig
from planner_adapter import TypedPlannerAdapter


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def safe_reset(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(mode=0o700, parents=True)


def seed(workspace: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        target = workspace.joinpath(*name.split("/"))
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def build_contract(spec: dict, provenance: Provenance) -> CompletionContractV2:
    artifacts = []
    for item in spec["artifacts"]:
        fields = tuple(
            SemanticField(field["name"], field["value"], field.get("mode", "contains"))
            for field in item["semantic_fields"]
        )
        artifacts.append(ArtifactExpectation(item["path"], semantic_fields=fields))
    return CompletionContractV2(
        required_artifacts=tuple(artifacts),
        allowed_mutations=tuple(item["path"] for item in spec["artifacts"]),
        required_milestones=tuple(spec["milestones"]),
        milestone_edges=tuple(tuple(edge) for edge in spec.get("milestone_edges", [])),
        expected_provenance=provenance,
    )


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fixture", required=True)
    p.add_argument("--sandbox", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--key-env", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--provider", default="openrouter")
    p.add_argument("--model-revision", default="live-shadow")
    p.add_argument("--reasoning", default="off", choices=("off", "low", "medium", "high"))
    p.add_argument("--max-output-tokens", type=int, default=1024)
    p.add_argument("--timeout-seconds", type=int, default=60)
    p.add_argument("--report", required=True)
    return p.parse_args(argv)


def expected_from(item: dict) -> ExpectedArtifact:
    return ExpectedArtifact(
        path=item["path"],
        content=item.get("content"),
        digest=item.get("digest"),
        absent=bool(item.get("absent", False)),
        contains=tuple(item["contains"]) if item.get("contains") else None,
    )


def count_event_type(path: Path, event_type: str) -> int:
    if not path.exists():
        return 0
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line).get("event_type") == event_type:
            count += 1
    return count


def main(argv=None) -> int:
    args = parse_args(argv)
    fixture_path = Path(args.fixture)
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    spec = fixture["shadow_contract"]
    sandbox = Path(args.sandbox)
    safe_reset(sandbox)
    workspace = sandbox / "workspace"
    workspace.mkdir(mode=0o700)
    seed(workspace, fixture["seed"])
    now = int(time.time())
    fault = fixture.get("fault")
    fault_state = {"remaining": int(fault["count"]) if fault is not None else 0}
    fault_action = fault["action_id"] if fault is not None else None

    def fault_hook(step, attempt_id, ordinal):
        if step.action_id == fault_action and fault_state["remaining"] > 0:
            fault_state["remaining"] -= 1
            raise RuntimeError("injected transient execution failure")

    run = build_run(fixture["task_id"], clock=lambda: now)
    harness = AgentHarness(
        run,
        workspace,
        sandbox / "agent-evidence.jsonl",
        actor_id="actor-live-shadow-001",
        workspace_id="workspace-live-shadow-001",
        clock=lambda: now,
        faults={} if fault_action is None else {fault_action: fault_hook},
    )
    config = OpenAICompatiblePlannerConfig(
        endpoint=args.endpoint,
        api_key_env=args.key_env,
        model_id=args.model,
        provider=args.provider,
        model_revision=args.model_revision,
        timeout_seconds=args.timeout_seconds,
        max_output_tokens=args.max_output_tokens,
        reasoning_effort=args.reasoning,
    )
    provenance = Provenance.from_dict(
        {
            "contract_revision": "live-shadow-1",
            "evaluator_digest": digest(Path(__file__).with_name("completion_contract_v2.py")),
            "fixture_digest": digest(fixture_path),
            "benchmark_commit": os.popen("git rev-parse HEAD").read().strip() or "0" * 40,
            "environment_digest": "sha256:" + hashlib.sha256(sys.version.encode()).hexdigest(),
            "model_id": args.model,
            "model_revision": args.model_revision,
            "reasoning_effort": args.reasoning,
            "max_output_tokens": args.max_output_tokens,
            "seed": fixture["task_id"],
            "trial_id": fixture["task_id"] + "-live-shadow",
        }
    )
    started = time.time()
    result = run_live_shadow(
        harness,
        fixture["goal"],
        TypedPlannerAdapter(OpenAICompatiblePlannerCaller(config)),
        contract=build_contract(spec, provenance),
        expectations=[expected_from(item) for item in fixture["expect"]],
        provenance=provenance,
        milestones=None,
        milestone_action_map=spec["milestone_action_map"],
    )
    report = {
        "schema_version": "northstar.live-shadow.v1",
        "task_outcome": result.task_outcome.as_dict(),
        "production": {
            "verdict": result.production.verdict,
            "errors": list(result.production.errors),
            "artifact_digests": result.production.artifact_digests,
        },
        "contract": result.contract.as_dict(),
        "layered": {
            "verdict": result.layered.verdict,
            "errors": list(result.layered.errors),
            "production_verdict": result.layered.production_verdict,
            "contract_verdict": result.layered.contract_verdict,
            "execution_authorized": result.layered.execution_authorized,
        },
        "before": result.before.as_dict(),
        "after": result.after.as_dict(),
        "elapsed_seconds": round(time.time() - started, 3),
        "fault": fault,
        "faults_injected": (int(fault["count"]) - fault_state["remaining"]) if fault is not None else 0,
        "action_failures": count_event_type(harness.evidence_path, "step.action_failed"),
        "model": args.model,
        "provider": args.provider,
        "fixture": str(fixture_path),
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"production": report["production"]["verdict"], "contract": report["contract"]["verdict"], "layered": report["layered"]["verdict"], "report": str(report_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
