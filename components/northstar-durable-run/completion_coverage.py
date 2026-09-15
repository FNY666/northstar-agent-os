"""Test-only requirement coverage audit for the completion contract.

The batch replay showed the real ceiling of the contract: a deliverable that
states its facts as prose with no machine-readable key/value lines cannot be
verified, and correctly returns ``insufficient_information``. That is the right
behaviour at completion time, but it is the wrong place to discover the
problem.

This module moves the discovery earlier. It compares the requirements the
archived fixture actually asserted against the semantic fields the host
declared, and names every requirement that no declared field can bind. Run it
before a run: a task whose deliverable format cannot express the required facts
is a task-authoring defect, not a verifier failure.

Coverage is reported from the archive, never asserted by hand. Requirements come
from the fixture's own ``expect`` block; a requirement counts as covered only
when some declared field's expected value contains it.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from completion_batch_replay import HostReplayContext, RunReplaySpec, TaskReplaySpec, load_spec


@dataclass(frozen=True)
class TaskCoverage:
    run: str
    task_id: str
    requirements: tuple[str, ...]
    covered: tuple[str, ...]
    uncovered: tuple[str, ...]
    declared_field_count: int

    @property
    def complete(self) -> bool:
        return not self.uncovered


def fixture_requirements(fixture: Mapping[str, Any]) -> tuple[str, ...]:
    """Read the values a fixture actually asserted, in declaration order."""
    if not isinstance(fixture, Mapping):
        raise ValueError("fixture must be an object")
    expect = fixture.get("expect")
    if not isinstance(expect, list):
        raise ValueError("fixture expectation is invalid")
    requirements: list[str] = []
    for entry in expect:
        if not isinstance(entry, Mapping):
            raise ValueError("fixture expectation entry is invalid")
        contains = entry.get("contains")
        if not isinstance(contains, list) or any(not isinstance(item, str) for item in contains):
            raise ValueError("fixture expectation values are invalid")
        for value in contains:
            if value not in requirements:
                requirements.append(value)
    return tuple(requirements)


def _is_covered(requirement: str, declared_values: Sequence[str]) -> bool:
    target = requirement.casefold()
    return any(target in value.casefold() for value in declared_values)


def audit_task(context: HostReplayContext, run: RunReplaySpec, spec: TaskReplaySpec) -> TaskCoverage:
    fixture_path = context.archive_root / run.run / spec.fixture
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    requirements = fixture_requirements(fixture)
    declared = [
        field.expected_value
        for fields in spec.semantic_fields.values()
        for field in fields
    ]
    covered = tuple(item for item in requirements if _is_covered(item, declared))
    uncovered = tuple(item for item in requirements if not _is_covered(item, declared))
    return TaskCoverage(
        run=run.run,
        task_id=spec.task_id,
        requirements=requirements,
        covered=covered,
        uncovered=uncovered,
        declared_field_count=len(declared),
    )


def audit(context: HostReplayContext, specs: Sequence[RunReplaySpec]) -> tuple[TaskCoverage, ...]:
    return tuple(
        audit_task(context, run, spec) for run in specs for spec in run.tasks
    )


def summarize(coverage: Sequence[TaskCoverage]) -> dict[str, Any]:
    entries = [
        {
            "run": item.run,
            "task_id": item.task_id,
            "requirement_count": len(item.requirements),
            "bound": len(item.covered),
            "uncovered": list(item.uncovered),
            "declared_field_count": item.declared_field_count,
            "complete": item.complete,
        }
        for item in coverage
    ]
    bound = sum(entry["bound"] for entry in entries)
    requirements = sum(entry["requirement_count"] for entry in entries)
    return {
        "tasks": entries,
        "task_count": len(entries),
        "complete": sum(1 for entry in entries if entry["complete"]),
        "requirement_count": requirements,
        "bound": bound,
        "unbound": requirements - bound,
        "all_bound": all(entry["complete"] for entry in entries),
        "gaps": [entry for entry in entries if not entry["complete"]],
    }


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    from completion_batch_replay import default_context

    parser = argparse.ArgumentParser(description="Audit semantic coverage of archived tasks.")
    parser.add_argument("--archive-root", default="/var/minis/shared/northstar-live-runs")
    parser.add_argument(
        "--spec", default=str(Path(__file__).with_name("replay") / "archive-replay-spec.json")
    )
    parser.add_argument("--json-out")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when any requirement cannot be bound by a declared field",
    )
    arguments = parser.parse_args(argv)

    context = default_context(
        Path(arguments.archive_root), Path(__file__).resolve().parent / "completion_contract_v2.py"
    )
    coverage = audit(context, load_spec(arguments.spec))
    summary = summarize(coverage)
    for item in coverage:
        state = "complete" if item.complete else "gap"
        print(
            f"[{state}] {item.run} {item.task_id}: "
            f"{len(item.covered)}/{len(item.requirements)} requirements bound "
            f"by {item.declared_field_count} declared field(s)"
        )
        for value in item.uncovered:
            print(f"        unbindable: {value!r}")
    print(
        f"total {summary['bound']}/{summary['requirement_count']} requirements bound; "
        f"{summary['complete']}/{summary['task_count']} tasks fully checkable"
    )
    if arguments.json_out:
        Path(arguments.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if arguments.strict and not summary["all_bound"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
