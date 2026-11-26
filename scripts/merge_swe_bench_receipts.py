#!/usr/bin/env python3
"""Join the per-instance receipts of a batch into one receipt per half.

The batch keeps one solve receipt and one evaluation receipt per instance,
so that an interrupted run can be resumed without redoing finished work.
A measurement record, though, has to describe one set of instances, so the
per-instance receipts are joined here into a single solve receipt and a
single evaluation receipt.

Only the instances that have both halves are joined: a measurement that
silently dropped half of its instances would not be a measurement of what
ran.  The script says which instances it left out and why.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def collect(out: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    """Return the joined solve receipt, the joined eval receipt and the gaps."""
    solve: dict[str, Any] = {}
    evaluate: dict[str, Any] = {}
    gaps: dict[str, str] = {}
    for path in sorted(out.glob("eval-*.json")):
        instance_id = path.stem[len("eval-"):]
        solve_path = out / f"solve-{instance_id}.json"
        if not solve_path.exists():
            gaps[instance_id] = "no solve receipt"
            continue
        eval_receipt = _load(path)
        solve_receipt = _load(solve_path)
        evaluate.setdefault("tasks", []).extend(eval_receipt.get("tasks", []))
        solve.setdefault("tasks", []).extend(solve_receipt.get("tasks", []))
    # The conditions of the first receipt describe the whole run: every
    # instance in a batch is solved with the same model and the same
    # settings.  They are checked rather than assumed.
    conditions = {}
    for path in sorted(out.glob("solve-*.json")):
        if path.name.endswith("-patches.json"):
            continue
        data = _load(path)
        found = data.get("conditions", {})
        if not conditions:
            conditions = found
        elif found != conditions:
            gaps[path.stem[len("solve-"):]] = "conditions differ from the rest of the batch"
    if solve:
        solve["conditions"] = conditions
        solve["real_model_evaluated"] = all(
            _load(path).get("real_model_evaluated", False)
            for path in out.glob("solve-*.json")
            if not path.name.endswith("-patches.json")
        )
    return solve, evaluate, gaps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, help="the directory the batch wrote to")
    parser.add_argument("--solve-output", required=True)
    parser.add_argument("--eval-output", required=True)
    arguments = parser.parse_args(argv)

    out = Path(arguments.batch)
    solve, evaluate, gaps = collect(out)
    if not solve.get("tasks"):
        print("no instance has both a solve receipt and an evaluation receipt")
        return 2
    Path(arguments.solve_output).write_text(
        json.dumps(solve, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    Path(arguments.eval_output).write_text(
        json.dumps(evaluate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps({
        "instances": len(solve["tasks"]),
        "evaluations": len(evaluate.get("tasks", [])),
        "left_out": gaps,
    }, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
