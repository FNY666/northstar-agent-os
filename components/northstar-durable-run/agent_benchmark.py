"""Task-level benchmark for the multi-step entry.

Component tests prove contracts; this proves whole tasks. Every fixture is a
host-owned definition (goal, steps, seed files, expected artifacts, optional
fault injection) and every run gets a fresh workspace and a fresh evidence
stream, so a task's success cannot depend on another task's leftovers.

The planner is a *scripted* caller: this measures the execution, recovery, and
verification harness, not model planning quality. Swapping in a real model
caller changes only the planner argument, which is exactly the seam a future
model benchmark would use.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agent_entry import AgentHarness, ExpectedArtifact, READ_ACTION, build_run
from agent_loop import PostconditionResult
from planner_adapter import PlannerModelResponse, TypedPlannerAdapter

SCHEMA = "northstar.agent-benchmark.v1"
DEFAULT_TASKS = Path(__file__).resolve().parent / "benchmarks" / "agent_tasks.json"
_FIXED_CLOCK = 100


@dataclass(frozen=True)
class BenchmarkTask:
    task_id: str
    goal: str
    steps: tuple[dict, ...]
    expects: tuple[ExpectedArtifact, ...]
    seed: dict[str, str]
    fault: str | None
    fault_action: str

    @classmethod
    def from_dict(cls, value: dict) -> "BenchmarkTask":
        known = {"task_id", "goal", "steps", "expect", "seed", "fault", "fault_action"}
        if not isinstance(value, dict) or set(value) - known:
            raise ValueError("benchmark task has unknown fields")
        for field in ("task_id", "goal", "steps"):
            if field not in value:
                raise ValueError(f"benchmark task is missing {field}")
        if not isinstance(value["steps"], list) or not value["steps"]:
            raise ValueError("benchmark task steps are invalid")
        action_ids = {step.get("action_id") for step in value["steps"]}
        if not action_ids <= {READ_ACTION, "workspace.write"}:
            raise ValueError("benchmark task uses an unknown action")
        expects = tuple(
            ExpectedArtifact(
                path=item["path"],
                content=item.get("content"),
                digest=item.get("digest"),
                absent=bool(item.get("absent", False)),
            )
            for item in value.get("expect", [])
        )
        seed = value.get("seed", {})
        if not isinstance(seed, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in seed.items()
        ):
            raise ValueError("benchmark task seed files are invalid")
        fault = value.get("fault")
        if fault not in {None, "fail_first_attempt", "unknown_once"}:
            raise ValueError("benchmark task fault is unknown")
        fault_action = value.get("fault_action", "workspace.write")
        return cls(
            task_id=value["task_id"],
            goal=value["goal"],
            steps=tuple(value["steps"]),
            expects=expects,
            seed=dict(seed),
            fault=fault,
            fault_action=fault_action,
        )


def load_tasks(path: str | Path = DEFAULT_TASKS) -> tuple[BenchmarkTask, ...]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA:
        raise ValueError("benchmark suite schema is invalid")
    tasks = value.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("benchmark suite has no tasks")
    parsed = tuple(BenchmarkTask.from_dict(item) for item in tasks)
    if len({task.task_id for task in parsed}) != len(parsed):
        raise ValueError("benchmark suite has duplicate task ids")
    return parsed


def plan_value(task: BenchmarkTask, run) -> dict:
    steps = []
    for step in task.steps:
        action = step["action_id"]
        steps.append(
            {
                "schema_version": "northstar.agent-plan-step.v1",
                "step_id": step["step_id"],
                "action_id": action,
                "input_payload": step["payload"],
                "scope_snapshot": [
                    "workspace:read" if action == READ_ACTION else "workspace:write"
                ],
                "expected_postconditions": list(step["postconditions"]),
                "idempotency_key": f"{task.task_id}-{step['step_id']}-1",
                "max_attempts": int(step.get("max_attempts", 2)),
                "deadline_at": run.deadline_at - 10,
            }
        )
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": f"plan-{task.task_id}",
        "plan_version": 1,
        "task_id": run.task_id,
        "thread_id": run.thread_id,
        "run_id": run.run_id,
        "actor_id": f"actor-{task.task_id}",
        "workspace_id": f"workspace-{task.task_id}",
        "policy_revision": "policy-benchmark-1",
        "trace_id": run.trace_id,
        "steps": steps,
    }


class ScriptedCaller:
    """Deterministic fixture caller with host-declared model identity."""

    def __init__(self, plan: dict):
        self.plan = plan

    def __call__(self, *, goal, context, repair_error, attempt):
        return PlannerModelResponse(
            json.dumps({"plan": self.plan}), "scripted-planner", "fixture", "rev-1"
        )


def run_task(task: BenchmarkTask, root: Path) -> dict:
    workspace = root / task.task_id / "workspace"
    workspace.mkdir(parents=True, mode=0o700)
    for name, content in task.seed.items():
        (workspace / name).write_text(content, encoding="utf-8")
    run = build_run(task.task_id, clock=lambda: _FIXED_CLOCK)
    faults = {}
    observer_hook = None
    if task.fault == "fail_first_attempt":
        def fail_first(step, attempt_id, ordinal, _action=task.fault_action):
            if ordinal == 1:
                raise RuntimeError("injected transient failure")

        faults[task.fault_action] = fail_first
    elif task.fault == "unknown_once":
        def unknown_once(step, attempt_id, ordinal):
            if ordinal == 1:
                return PostconditionResult("unknown", "injected_observer_unknown")
            return None

        observer_hook = unknown_once
    harness = AgentHarness(
        run,
        workspace,
        root / task.task_id / "evidence.jsonl",
        actor_id=f"actor-{task.task_id}",
        workspace_id=f"workspace-{task.task_id}",
        policy_revision="policy-benchmark-1",
        clock=lambda: _FIXED_CLOCK,
        faults=faults,
        observer_hook=observer_hook,
    )
    planner = TypedPlannerAdapter(ScriptedCaller(plan_value(task, run)))
    outcome = harness.run_goal(task.goal, planner, expectations=task.expects)
    record = outcome.as_dict()
    record["fault"] = task.fault
    record["expectations"] = [artifact.path for artifact in task.expects]
    return record


def run_benchmark(tasks, *, workdir: str | Path | None = None) -> dict:
    tasks = tuple(tasks)
    with tempfile.TemporaryDirectory(dir=workdir) as temporary:
        root = Path(temporary)
        records = [run_task(task, root) for task in tasks]
    ok = [record for record in records if record["ok"]]
    injected = [record for record in records if record["fault"]]
    recovered = [record for record in injected if record["ok"]]
    steps = [step for record in records for step in record["steps"]]
    return {
        "schema_version": SCHEMA,
        "planner": "scripted-fixture",
        "tasks": records,
        "summary": {
            "total": len(records),
            "finished": sum(1 for record in records if record["run_status"] == "finished"),
            "verified": sum(
                1 for record in records if record["verification"]["verdict"] == "verified"
            ),
            "ok": len(ok),
            "success_rate": round(len(ok) / len(records), 4) if records else 0.0,
            "steps": len(steps),
            "steps_verified": sum(
                1 for step in steps if step["status"] == "verified_committed"
            ),
            "faults_injected": len(injected),
            "faults_recovered": len(recovered),
        },
    }


def format_report(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"planner={report['planner']} tasks={summary['total']} ok={summary['ok']} "
        f"success_rate={summary['success_rate']}",
        f"finished={summary['finished']} verified={summary['verified']} "
        f"steps={summary['steps_verified']}/{summary['steps']} "
        f"faults_recovered={summary['faults_recovered']}/{summary['faults_injected']}",
    ]
    for record in report["tasks"]:
        marker = "ok  " if record["ok"] else "FAIL"
        lines.append(
            f"  {marker} {record['task_id']}: run={record['run_status']} "
            f"verification={record['verification']['verdict']} "
            f"resumes={record['resumes']} events={record['evidence_events']}"
        )
        for failure in record["verification"]["failures"]:
            lines.append(f"       - {failure}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the multi-step agent benchmark.")
    parser.add_argument("--tasks", default=str(DEFAULT_TASKS))
    parser.add_argument("--out", default=None, help="write the JSON report here")
    arguments = parser.parse_args(argv)
    report = run_benchmark(load_tasks(arguments.tasks))
    print(format_report(report))
    if arguments.out:
        Path(arguments.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["summary"]["ok"] == report["summary"]["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
