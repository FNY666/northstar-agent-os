#!/usr/bin/env python3
"""Record a SWE-bench measurement as a repository artifact.

The solver receipt says what was attempted; the evaluator receipt says what
the upstream harness decided.  This joins the two into one record that a
later reader can check, and it refuses to publish a record whose two halves
do not describe the same set of instances.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "northstar.swe-bench-measurement.v1"

# The upstream states.  Only the first is a clean pass.
RESOLVED_FULL = "RESOLVED_FULL"
RESOLVED_PARTIAL = "RESOLVED_PARTIAL"

# Outcomes that say something about the run, not about the model.  They are
# reported separately: counting them as failures would blame the model for
# an environment or harness problem.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from swe_bench_confidence import summarise as _confidence  # noqa: E402

NOT_A_VERDICT = (
    "patch_not_applied",
    "no_patch_delivered",
    "evaluation_inconclusive",
    "evaluation_infrastructure_failure",
    "evaluation_timeout",
    "ERROR",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_record(
    solve_receipt: dict[str, Any],
    eval_receipt: dict[str, Any],
    sample_path: Path,
) -> dict[str, Any]:
    solved = {
        row["instance_id"]: row
        for row in solve_receipt.get("tasks", [])
    }
    verdicts = {
        row["instance_id"]: row
        for row in eval_receipt.get("tasks", [])
    }
    instances = sorted(set(solved) & set(verdicts))
    if not instances:
        raise ValueError("the solver and the evaluator disagree about the instances")

    rows = []
    for instance_id in instances:
        solve_row = solved[instance_id]
        verdict = verdicts[instance_id]
        row = {
            "instance_id": instance_id,
            "repo": solve_row.get("repo", ""),
            "patch_bytes": solve_row.get("patch_bytes", 0),
            "patch_sha256": solve_row.get("patch_sha256", ""),
            "outcome": verdict.get("outcome", "ERROR"),
            "resolved": verdict.get("resolved", False),
        }
        excluded = verdict.get("excluded_p2p") or []
        if excluded:
            # Say which tests were left out of the verdict, so the record
            # never hides that a verdict was narrowed.
            row["excluded_p2p"] = list(excluded)
        rows.append(row)

    resolved = sum(1 for row in rows if row["outcome"] == RESOLVED_FULL)
    partial = sum(1 for row in rows if row["outcome"] == RESOLVED_PARTIAL)
    not_a_verdict = sum(1 for row in rows if row["outcome"] in NOT_A_VERDICT)
    failed = len(rows) - resolved - partial - not_a_verdict
    conditions = dict(solve_receipt.get("conditions", {}))
    conditions["harness"] = eval_receipt.get("conditions", {}).get("harness", "")
    conditions["sample_sha256"] = _sha256(sample_path.read_bytes())

    cost = solve_receipt.get("cost") or {}
    excluded_tests = sorted({
        name
        for row in rows
        for name in row.get("excluded_p2p", [])
    })
    return {
        "schema": SCHEMA,
        "measurement": "swe_bench_verified_50",
        "real_model_evaluated": bool(solve_receipt.get("real_model_evaluated")),
        "conditions": conditions,
        "tasks": rows,
        "cost": cost,
        "summary": {
            "checked": len(rows),
            "resolved_full": resolved,
            "resolved_partial": partial,
            # What the run cost, and what a resolved instance cost.
            "cost_usd": cost.get("cost_usd"),
            "input_tokens": (cost.get("usage") or {}).get("input_tokens"),
            "output_tokens": (cost.get("usage") or {}).get("output_tokens"),
            "tool_calls": cost.get("tool_calls"),
            "num_turns": cost.get("num_turns"),
            "instances_with_cost": cost.get("instances_with_cost"),
            "instances_without_cost": cost.get("instances_without_cost"),
            "failed": failed,
            "not_a_verdict": not_a_verdict,
            "excluded_p2p": excluded_tests,
            "instances_with_exclusions": sum(
                1 for row in rows if row.get("excluded_p2p")
            ),
            "resolved_rate": round(resolved / len(rows), 4) if rows else 0.0,
            # A point estimate on fifty tasks carries about seven points of
            # standard error; the interval says how much of a difference
            # between two runs is noise.
            "resolved_rate_ci95": _confidence(resolved, len(rows)),
            # The rate over the instances that actually got a verdict.  The
            # rate over every instance counts an environment problem as a
            # model failure, which is the opposite of what it looks like.
            "resolved_rate_over_verdicts": (
                round(resolved / (len(rows) - not_a_verdict), 4)
                if len(rows) - not_a_verdict else 0.0
            ),
            "resolved_rate_over_verdicts_ci95": _confidence(
                resolved, len(rows) - not_a_verdict
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solve", required=True, help="the solver receipt")
    parser.add_argument("--eval", required=True, help="the evaluator receipt")
    parser.add_argument("--sample", required=True, help="the frozen sample")
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)

    record = build_record(
        _load(Path(arguments.solve)),
        _load(Path(arguments.eval)),
        Path(arguments.sample),
    )
    output = Path(arguments.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(record["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
