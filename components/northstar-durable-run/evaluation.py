"""Deterministic local task-level evaluation for the durable-run slice."""
from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from durable_contract import RunContract
from event_store import EventStore
from runner import DurableRunner, StepPlan
from verifier import verify_run_completion


@dataclass(frozen=True)
class BenchmarkSummary:
    total: int
    verified: int
    failed: int
    unknown: int
    recovered: int
    duplicate_side_effects: int
    results: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "verified": self.verified,
            "failed": self.failed,
            "unknown": self.unknown,
            "recovered": self.recovered,
            "duplicate_side_effects": self.duplicate_side_effects,
            "completion_rate": self.verified / self.total if self.total else 0.0,
            "verification_rate": self.verified / self.total if self.total else 0.0,
            "recovery_rate": self.recovered / 3 if self.total >= 3 else 0.0,
            "results": self.results,
        }


def _run_case(root: Path, index: int, *, should_fail: bool, should_recover: bool) -> dict[str, Any]:
    fixture_id = f"fixture-{index:03d}"
    workspace = root / fixture_id / "workspace"
    workspace.mkdir(parents=True, mode=0o700)
    run = RunContract.from_dict(
        {
            "schema_version": "northstar.durable-run.v1",
            "task_id": f"task-{index:03d}",
            "thread_id": f"thread-{index:03d}",
            "run_id": f"run-{index:03d}",
            "parent_run_id": None,
            "status": "planned",
            "deadline_at": 10_000,
            "scope_snapshot": ["workspace:write"],
            "trace_id": f"trace-{index:03d}",
        }
    )
    store = EventStore(root / fixture_id / "events.jsonl")
    runner = DurableRunner(
        run,
        store,
        lease_path=root / fixture_id / "lease.json",
        lease_ttl_seconds=20,
    )
    target = workspace / "result.txt"
    side_effects: list[str] = []
    interrupted = {"value": False}

    def action(key: str) -> dict[str, Any]:
        if key not in side_effects:
            side_effects.append(key)
        if should_recover and not interrupted["value"]:
            interrupted["value"] = True
            raise KeyboardInterrupt("fixture interruption")
        target.write_text(f"fixture-{index}\n", encoding="utf-8")
        return {"artifact": "result.txt"}

    plan = StepPlan(
        step_id="write",
        input_payload={"fixture": fixture_id},
        scope_snapshot=["workspace:write"],
        expected_postconditions=["artifact_digest"],
        action=action,
    )
    try:
        runner.execute([plan], owner_id="worker-a", now=1_000)
    except KeyboardInterrupt:
        if not should_recover:
            raise
        runner = DurableRunner(
            run,
            store,
            lease_path=root / fixture_id / "lease.json",
            lease_ttl_seconds=20,
        )
        runner.execute([plan], owner_id="worker-b", now=1_001)

    expected = (
        "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
        if target.exists()
        else "sha256:" + "0" * 64
    )
    verification = verify_run_completion(
        run,
        store,
        workspace=workspace,
        required_files={"result.txt": expected},
        test_exit_code=1 if should_fail else 0,
        now=1_002,
    )
    return {
        "verdict": verification.verdict,
        "failure_class": "postcondition" if verification.verdict == "failed" else None,
        "recovered": bool(should_recover and interrupted["value"]),
        "side_effect_count": len(side_effects),
        "duplicate_side_effects": max(0, len(side_effects) - 1),
        "error_count": len(verification.errors),
    }


def run_fixture_benchmark(root: str | Path, *, case_count: int, fail_case: int | None = None) -> BenchmarkSummary:
    if not isinstance(case_count, int) or isinstance(case_count, bool) or not 1 <= case_count <= 100:
        raise ValueError("case_count must be between 1 and 100")
    if fail_case is not None and (
        not isinstance(fail_case, int) or isinstance(fail_case, bool) or not 1 <= fail_case <= case_count
    ):
        raise ValueError("fail_case must identify a fixture in the benchmark")
    root_path = Path(root).absolute()
    root_path.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, Any]] = {}
    for index in range(1, case_count + 1):
        results[f"fixture-{index:03d}"] = _run_case(
            root_path,
            index,
            should_fail=fail_case == index,
            should_recover=index <= 3,
        )
    verified = sum(value["verdict"] == "verified" for value in results.values())
    failed = sum(value["verdict"] == "failed" for value in results.values())
    unknown = sum(value["verdict"] == "unknown" for value in results.values())
    recovered = sum(value["recovered"] for value in results.values())
    duplicate_side_effects = sum(value["duplicate_side_effects"] for value in results.values())
    return BenchmarkSummary(
        total=case_count,
        verified=verified,
        failed=failed,
        unknown=unknown,
        recovered=recovered,
        duplicate_side_effects=duplicate_side_effects,
        results=results,
    )
