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
import json
import os
import shutil
import sys
import time
from pathlib import Path

from agent_driver import AgentDriver, DriverBudget
from agent_entry import ExpectedArtifact
from completion_advisory import (
    contract_from_spec,
    evaluate_driver_advisory,
    provenance_from,
)
from completion_workspace_snapshot import WorkspaceObservationRefused, observe_workspace
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


def observe_or_none(root: Path):
    """Observation can refuse a tree it cannot vouch for; that is not a failure."""
    try:
        return observe_workspace(root)
    except WorkspaceObservationRefused:
        return None


def build_shadow_advisory(
    *,
    fixture: dict,
    fixture_path: str | Path,
    outcome,
    sandbox: Path,
    before,
    after,
    model_id: str,
    model_revision: str,
    reasoning_effort: str,
    max_output_tokens: int,
) -> dict | None:
    """Compute the read-only advisory, or explain why it is unavailable.

    Returns ``None`` when the fixture does not declare a shadow contract, so a
    fixture without one produces a report identical to before this existed. The
    result is never consulted when deciding success: an unavailable or failing
    advisory is recorded as data and the production verdict stands.
    """
    spec = fixture.get("shadow_contract")
    if not spec:
        return None
    unavailable = {
        "schema_version": "northstar.completion-advisory.v1",
        "authoritative": False,
        "affects_task_outcome": False,
        "execution_authorized": False,
        "available": False,
    }
    if before is None or after is None:
        return {**unavailable, "reason": "workspace_observation_unavailable"}
    if not outcome.rounds:
        return {**unavailable, "reason": "no_completed_round"}
    last = outcome.rounds[-1]
    evidence_path = sandbox / "evidence" / f"round-{last.round_index}.evidence.jsonl"
    try:
        provenance = provenance_from(
            contract_revision="live-run-advisory-1",
            fixture_path=fixture_path,
            evaluator_path=Path(__file__).with_name("completion_contract_v2.py"),
            model_id=model_id,
            model_revision=model_revision,
            reasoning_effort=reasoning_effort,
            max_output_tokens=max_output_tokens,
            seed=fixture["task_id"],
            trial_id=fixture["task_id"] + "-run-advisory",
        )
        advisory = evaluate_driver_advisory(
            contract=contract_from_spec(spec, provenance),
            provenance=provenance,
            verification=outcome.verification,
            run_status=last.status,
            before=before,
            after=after,
            evidence_path=evidence_path,
            milestone_action_map=spec.get("milestone_action_map"),
            round_steps=last.steps,
        )
    except Exception as error:  # noqa: BLE001 - see below
        # Deliberately broad: the advisory is non-authoritative, so no failure of
        # it may break the production run. A bug in a malformed fixture spec shows
        # up as a distinctive recorded reason (``advisory_error:KeyError``) rather
        # than as a crash in the path that actually decides success.
        return {**unavailable, "reason": f"advisory_error:{type(error).__name__}"}
    return {**advisory.as_report_dict(), "available": True}


def build_parser() -> argparse.ArgumentParser:
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
    # Low-credit-safe defaults: OpenRouter reserves max_tokens up front, and
    # reasoning models can consume the whole budget before emitting JSON.
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--reasoning", default="off", choices=["off", "low", "medium", "high"])
    return parser


def main(argv=None) -> int:
    parser = build_parser()
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
    before = observe_or_none(workspace)
    outcome = driver.run(task_id, goal, TypedPlannerAdapter(caller))
    after = observe_or_none(workspace)
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
    advisory = build_shadow_advisory(
        fixture=fixture,
        fixture_path=arguments.fixture,
        outcome=outcome,
        sandbox=sandbox,
        before=before,
        after=after,
        model_id=arguments.model,
        model_revision=arguments.model_revision,
        reasoning_effort=arguments.reasoning,
        max_output_tokens=arguments.max_output_tokens,
    )
    if advisory is not None:
        report["shadow_advisory"] = advisory
    rendered = json.dumps(report, indent=2)
    if arguments.report:
        Path(arguments.report).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    # The production gate alone decides this; the advisory is recorded, never read.
    return 0 if outcome.ok else 1


if __name__ == "__main__":
    sys.exit(main())
