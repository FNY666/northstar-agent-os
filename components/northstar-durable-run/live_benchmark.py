"""Bounded multi-task benchmark for the real planner path.

The benchmark deliberately reuses AgentDriver for execution and verification.
Its only responsibilities are fixture validation, fresh per-task sandboxes, and
provider usage accounting. It never records request credentials or message
content.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path
from typing import Any, Callable

from agent_driver import AgentDriver, DriverBudget
from agent_entry import AgentHarness, ExpectedArtifact
from openai_compatible_planner import (
    OpenAICompatiblePlannerCaller,
    OpenAICompatiblePlannerConfig,
)
from planner_adapter import TypedPlannerAdapter

SCHEMA = "northstar.live-task.v1"
REPORT_SCHEMA = "northstar.live-benchmark.v1"


def _seed_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("live task seed path is invalid")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or "\\" in part or "\x00" in part for part in parts):
        raise ValueError("live task seed path is invalid")
    return value


def _validate_fault(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"action_id", "count"}:
        raise ValueError("live task fault is invalid")
    action_id = value["action_id"]
    count = value["count"]
    if action_id not in {"workspace.list", "repo.read", "workspace.write"}:
        raise ValueError("live task fault action is invalid")
    if type(count) is not int or not 1 <= count <= 3:
        raise ValueError("live task fault count is invalid")
    return {"action_id": action_id, "count": count}


def _expectation(value: Any) -> ExpectedArtifact:
    if not isinstance(value, dict) or set(value) - {"path", "content", "digest", "absent", "contains"}:
        raise ValueError("live expectation is invalid")
    if "path" not in value:
        raise ValueError("live expectation has no path")
    contains = tuple(value["contains"]) if "contains" in value else None
    return ExpectedArtifact(
        path=value["path"],
        content=value.get("content"),
        digest=value.get("digest"),
        absent=bool(value.get("absent", False)),
        contains=contains,
    )


def _validate_task(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("live task must be an object")
    if value.get("schema_version", SCHEMA) != SCHEMA:
        raise ValueError("live task schema is invalid")
    task_id = value.get("task_id")
    goal = value.get("goal")
    seed = value.get("seed", {})
    expects = value.get("expect", [])
    if not isinstance(task_id, str) or not task_id or "/" in task_id or "\\" in task_id:
        raise ValueError("live task id is invalid")
    if not isinstance(goal, str) or not goal.strip():
        raise ValueError("live task goal is invalid")
    if not isinstance(seed, dict) or any(
        not isinstance(content, str)
        for content in seed.values()
    ):
        raise ValueError("live task seed is invalid")
    for path in seed:
        _seed_path(path)
    if not isinstance(expects, list):
        raise ValueError("live task expectations are invalid")
    parsed = [_expectation(item) for item in expects]
    fault = _validate_fault(value.get("fault"))
    result = dict(value)
    result["expect"] = parsed
    result["fault"] = fault
    return result


def load_live_tasks(path: str | Path) -> tuple[dict[str, Any], ...]:
    root = Path(path)
    files = [root] if root.is_file() else sorted(root.glob("*.json"))
    if not files:
        raise ValueError("live task path contains no JSON fixtures")
    tasks = tuple(_validate_task(json.loads(file.read_text(encoding="utf-8"))) for file in files)
    ids = [task["task_id"] for task in tasks]
    if len(set(ids)) != len(ids):
        raise ValueError("live task ids are not unique")
    return tasks


class UsageRecorderTransport:
    """Wrap one OpenAI-compatible transport and retain usage only."""

    def __init__(self, transport: Callable[[Any, float], bytes]):
        if not callable(transport):
            raise ValueError("transport must be callable")
        self.transport = transport
        self.records: list[dict[str, Any]] = []

    def __call__(self, request, timeout: float) -> bytes:
        raw = self.transport(request, timeout)
        try:
            payload = json.loads(raw.decode("utf-8"))
            usage = payload.get("usage")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            usage = None
        if isinstance(usage, dict):
            record = {}
            for field in ("cost", "prompt_tokens", "completion_tokens", "total_tokens"):
                value = usage.get(field)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    record[field] = value
            self.records.append(record)
        return raw


def _default_transport(request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _seed(workspace: Path, seed: dict[str, str]) -> None:
    workspace.mkdir(parents=True, mode=0o700)
    for relative, content in seed.items():
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _sum_usage(records: list[dict[str, Any]]) -> dict[str, Any]:
    result = {
        "cost": 0.0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }
    for record in records:
        for key in result:
            value = record.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                result[key] += value
    return result


def _count_action_failures(evidence_dir: Path) -> int:
    """Count only task-scoped evidence events; malformed evidence fails closed."""
    count = 0
    for path in sorted(evidence_dir.glob("round-*.evidence.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise ValueError("benchmark evidence cannot be read") from error
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError("benchmark evidence is malformed") from error
            if not isinstance(event, dict):
                raise ValueError("benchmark evidence event is invalid")
            if event.get("event_type") == "step.action_failed":
                count += 1
    return count


def _fault_hook(state: dict[str, int], action_id: str) -> Callable[..., None]:
    """Return a host-only hook that fails an action a bounded number of times."""
    def fail(step, attempt_id, ordinal):
        if step.action_id == action_id and state["remaining"] > 0:
            state["remaining"] -= 1
            raise RuntimeError("injected transient execution failure")

    return fail


def _run_one(
    task: dict[str, Any],
    *,
    endpoint: str,
    key_env: str,
    model: str,
    provider: str,
    model_revision: str,
    reasoning_effort: str | None,
    max_output_tokens: int,
    sandbox: Path,
    transport_factory: Callable[[dict[str, Any]], Callable[[Any, float], bytes]] | None,
) -> dict[str, Any]:
    task_root = sandbox / task["task_id"]
    if task_root.exists():
        raise ValueError(f"task sandbox already exists: {task['task_id']}")
    workspace = task_root / "workspace"
    _seed(workspace, task.get("seed", {}))
    expectations = tuple(task["expect"])
    recorder = UsageRecorderTransport(
        transport_factory(task) if transport_factory is not None else _default_transport
    )
    caller = OpenAICompatiblePlannerCaller(
        OpenAICompatiblePlannerConfig(
            endpoint=endpoint,
            api_key_env=key_env,
            model_id=model,
            provider=provider,
            model_revision=model_revision,
            timeout_seconds=180.0,
            max_output_tokens=max_output_tokens,
            reasoning_effort=reasoning_effort,
        ),
        transport=recorder,
    )
    fault = task.get("fault")
    fault_state = {"remaining": fault["count"] if fault is not None else 0}
    fault_action = fault["action_id"] if fault is not None else None
    hook = _fault_hook(fault_state, fault_action) if fault_action is not None else None

    def harness_builder(run, evidence_path):
        faults = {} if hook is None else {fault_action: hook}
        return AgentHarness(
            run,
            workspace,
            evidence_path,
            actor_id="actor-agent-001",
            workspace_id="workspace-agent-001",
            policy_revision="policy-agent-1",
            faults=faults,
        )

    driver = AgentDriver(
        workspace_root=workspace,
        evidence_dir=task_root / "evidence",
        expectations=expectations,
        budget=DriverBudget(
            max_rounds=int(task.get("rounds", 3)),
            max_observation_bytes=int(task.get("max_observation_bytes", 2_048)),
        ),
        harness_builder=harness_builder,
    )
    outcome = driver.run(task["task_id"], task["goal"], TypedPlannerAdapter(caller))
    action_failures = _count_action_failures(task_root / "evidence")
    declared_faults = fault["count"] if fault is not None else 0
    faults_injected = declared_faults - fault_state["remaining"]
    result = outcome.as_dict()
    result["fault"] = fault
    result["faults_injected"] = faults_injected
    result["action_failures"] = action_failures
    result["recovered_after_action_failure"] = bool(
        faults_injected > 0 and action_failures > 0 and outcome.ok
    )
    result["usage"] = _sum_usage(recorder.records)
    result["usage_calls"] = len(recorder.records)
    result["workspace"] = str(workspace)
    result["evidence_dir"] = str(task_root / "evidence")
    return result


def run_live_benchmark(
    tasks: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    endpoint: str,
    key_env: str,
    model: str,
    provider: str,
    model_revision: str,
    reasoning_effort: str | None,
    max_output_tokens: int,
    sandbox: str | Path,
    transport_factory: Callable[[dict[str, Any]], Callable[[Any, float], bytes]] | None = None,
) -> dict[str, Any]:
    root = Path(sandbox)
    if root.exists():
        raise ValueError("benchmark sandbox already exists")
    root.mkdir(parents=True, mode=0o700)
    records = [
        _run_one(
            task,
            endpoint=endpoint,
            key_env=key_env,
            model=model,
            provider=provider,
            model_revision=model_revision,
            reasoning_effort=reasoning_effort,
            max_output_tokens=max_output_tokens,
            sandbox=root,
            transport_factory=transport_factory,
        )
        for task in tasks
    ]
    total = len(records)
    successful = [record for record in records if record["ok"]]
    usage = _sum_usage([record["usage"] for record in records])
    return {
        "schema_version": REPORT_SCHEMA,
        "model": model,
        "provider": provider,
        "planner": "openai-compatible",
        "tasks": records,
        "summary": {
            "total": total,
            "ok": len(successful),
            "success_rate": round(len(successful) / total, 4) if total else 0.0,
            "total_rounds": sum(record["round_count"] for record in records),
            "total_model_calls": sum(record["model_calls"] for record in records),
            "recovered_tasks": sum(1 for record in records if record["round_count"] > 1 and record["ok"]),
            "fault_tasks": sum(1 for record in records if record["fault"] is not None),
            "faults_injected": sum(record["faults_injected"] for record in records),
            "action_failures": sum(record["action_failures"] for record in records),
            "recovered_after_action_failure": sum(
                1 for record in records if record["recovered_after_action_failure"]
            ),
            "total_cost": usage["cost"],
            "prompt_tokens": usage["prompt_tokens"],
            "completion_tokens": usage["completion_tokens"],
            "total_tokens": usage["total_tokens"],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded real-model tasks.")
    parser.add_argument("--tasks", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--key-env", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider", default="openai-compatible")
    parser.add_argument("--model-revision", default="rev-1")
    # Match live_run.py: low-credit-safe defaults for OpenRouter reservation
    # and reasoning models that can consume the entire output budget.
    parser.add_argument("--reasoning", default="off", choices=["off", "low", "medium", "high"])
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--max-tasks", type=int, default=None)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    tasks = load_live_tasks(args.tasks)
    if args.max_tasks is not None:
        if not 1 <= args.max_tasks <= len(tasks):
            raise ValueError("max-tasks is invalid")
        tasks = tasks[: args.max_tasks]
    report = run_live_benchmark(
        tasks,
        endpoint=args.endpoint,
        key_env=args.key_env,
        model=args.model,
        provider=args.provider,
        model_revision=args.model_revision,
        reasoning_effort=args.reasoning,
        max_output_tokens=args.max_output_tokens,
        sandbox=args.sandbox,
    )
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0 if report["summary"]["ok"] == report["summary"]["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
