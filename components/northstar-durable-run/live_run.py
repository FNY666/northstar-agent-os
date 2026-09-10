"""Run one real-model task through the governed driver.

This is the live counterpart of the hermetic tests: it seeds a private
workspace from a fixture, calls a real OpenAI-compatible model for each plan,
executes the admitted steps through the same authorization, tool, and
observation chain, and writes a report next to the evidence streams.

The model sees only the published planner context (identity, budget, tool
schema, host observations). It never receives credentials, and the host
verifies the deliverable itself, so a confident model answer is not evidence.

Usage:
    OPENROUTER_API_KEY=... python3 live_run.py \
        --fixture live/first_live_task.json \
        --endpoint https://openrouter.ai/api/v1/chat/completions \
        --key-env OPENROUTER_API_KEY \
        --model deepseek/deepseek-v4-pro \
        --sandbox /tmp/northstar-live \
        --report /tmp/northstar-live/report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

from agent_driver import AgentDriver, DriverBudget
from agent_entry import ExpectedArtifact
from openai_compatible_planner import (
    OpenAICompatiblePlannerCaller,
    OpenAICompatiblePlannerConfig,
)
from planner_adapter import TypedPlannerAdapter


def expected_from(item: dict) -> ExpectedArtifact:
    return ExpectedArtifact(
        path=item["path"],
        content=item.get("content"),
        digest=item.get("digest"),
        absent=bool(item.get("absent", False)),
        contains=tuple(item["contains"]) if item.get("contains") else None,
    )


def fresh_directory(path: Path) -> None:
    """Every run gets a clean sandbox: stale evidence would collide with it."""
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, mode=0o700)


def seed_workspace(root: Path, seed: dict[str, str]) -> None:
    fresh_directory(root)
    for name, content in seed.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run one real-model task through the driver.")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--key-env", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider", default="openai-compatible")
    parser.add_argument("--model-revision", default="rev-1")
    parser.add_argument("--sandbox", required=True, help="directory that will hold the workspace")
    parser.add_argument("--report", default=None)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--reasoning", default=None, choices=[None, "off", "low", "medium", "high"])
    arguments = parser.parse_args(argv)

    fixture = json.loads(Path(arguments.fixture).read_text(encoding="utf-8"))
    task_id = fixture["task_id"]
    goal = fixture["goal"]
    budget = DriverBudget(
        max_rounds=int(fixture.get("rounds", 3)),
        max_observation_bytes=int(fixture.get("max_observation_bytes", 2048)),
    )
    sandbox = Path(arguments.sandbox)
    fresh_directory(sandbox)
    workspace = sandbox / "workspace"
    seed_workspace(workspace, fixture.get("seed", {}))
    expectations = [expected_from(item) for item in fixture.get("expect", [])]

    caller = OpenAICompatiblePlannerCaller(
        OpenAICompatiblePlannerConfig(
            endpoint=arguments.endpoint,
            api_key_env=arguments.key_env,
            model_id=arguments.model,
            provider=arguments.provider,
            model_revision=arguments.model_revision,
            timeout_seconds=arguments.timeout_seconds,
            max_output_tokens=arguments.max_output_tokens,
            reasoning_effort=arguments.reasoning,
        )
    )
    driver = AgentDriver(
        workspace_root=workspace,
        evidence_dir=sandbox / "evidence",
        expectations=expectations,
        budget=budget,
        allowed_write_paths=None,
    )
    started = time.time()
    outcome = driver.run(task_id, goal, TypedPlannerAdapter(caller))
    report = outcome.as_dict()
    report.update(
        {
            "schema_version": "northstar.live-run.v1",
            "model": arguments.model,
            "provider": arguments.provider,
            "endpoint_host": arguments.endpoint.split("/")[2],
            "fixture": str(arguments.fixture),
            "elapsed_seconds": round(time.time() - started, 2),
            "sandbox": str(sandbox),
            "workspace_root": str(workspace),
            "api_key_env": arguments.key_env,
            "api_key_present": bool(os.environ.get(arguments.key_env)),
        }
    )
    report["deliverables"] = {
        record["round"]: sorted(record["observed"]) for record in report["rounds"]
    }
    rendered = json.dumps(report, indent=2)
    if arguments.report:
        Path(arguments.report).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if outcome.ok else 1


if __name__ == "__main__":
    sys.exit(main())
