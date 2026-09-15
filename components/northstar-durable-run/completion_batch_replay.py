"""Test-only batch replay of archived Northstar runs through Completion Contract v2.

This module answers one question: when the test-only contract is fed real
archived runs, does it misjudge legitimate completions?

Two independent passes are compared:

``digest``
    The artifact must hash to a digest the final round of the run actually
    committed in its evidence journal. This is host-owned ground truth taken
    from the archive, not from the report.

``semantic``
    The artifact must satisfy host-declared semantic fields parsed from its own
    content, with explicit negation rejected.

Nothing here reads the report's ``ok`` or ``verification`` fields.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from completion_contract_v2 import (
    ArtifactExpectation,
    CompletionContractV2,
    Provenance,
    SemanticField,
    WorkspaceSnapshot,
)
from completion_replay import ReplayConfig, replay_task_report
from completion_workspace_snapshot import materialize_workspace, observe_workspace

_DIGEST_PREFIX = "sha256:"
_MODES = ("digest", "semantic")
# The archived runs recorded token usage but not their model budget, reasoning
# effort, or model revision. The envelope therefore describes the host-declared
# replay conditions, and that gap is reported rather than papered over.
PROVENANCE_SCOPE_NOTE = (
    "provenance describes host-declared replay conditions; the archived runs did "
    "not record original max_output_tokens, reasoning_effort, or model revision"
)
_REPLAY_ENVELOPE_MAX_OUTPUT_TOKENS = 2048


@dataclass(frozen=True)
class SemanticRequirement:
    """A host-declared field that the deliverable must state and not negate."""

    name: str
    expected_value: str
    mode: str = "contains"


@dataclass(frozen=True)
class TaskReplaySpec:
    task_id: str
    fixture: str
    evidence: str
    artifacts: Mapping[str, str]
    milestone_labels: tuple[str, ...]
    milestone_edges: tuple[tuple[str, str], ...]
    semantic_fields: Mapping[str, tuple[SemanticRequirement, ...]]


@dataclass(frozen=True)
class RunReplaySpec:
    run: str
    report: str
    tasks: tuple[TaskReplaySpec, ...]


@dataclass(frozen=True)
class HostReplayContext:
    """Host-owned run conditions shared by every replayed task."""

    archive_root: Path
    evaluator_path: Path
    benchmark_commit: str
    environment_digest: str
    model_id: str
    model_revision: str
    reasoning_effort: str
    max_output_tokens: int
    run_seed: str


@dataclass(frozen=True)
class TaskReplayOutcome:
    run: str
    task_id: str
    mode: str
    verdict: str
    errors: tuple[str, ...]
    artifact_bound: bool
    milestones: tuple[str, ...]
    declared_fields: int


def _sha256(raw: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(raw).hexdigest()


def load_spec(path: str | Path) -> tuple[RunReplaySpec, ...]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    runs = []
    for item in raw["runs"]:
        tasks = []
        for task in item["tasks"]:
            semantics = {
                artifact: tuple(
                    SemanticRequirement(name=name, expected_value=value, mode=mode)
                    for name, value, mode in fields
                )
                for artifact, fields in (task.get("semantic_fields") or {}).items()
            }
            tasks.append(
                TaskReplaySpec(
                    task_id=task["task_id"],
                    fixture=task["fixture"],
                    evidence=task["evidence"],
                    artifacts=dict(task["artifacts"]),
                    milestone_labels=tuple(task["milestone_labels"]),
                    milestone_edges=tuple(tuple(edge) for edge in task["milestone_edges"]),
                    semantic_fields=semantics,
                )
            )
        runs.append(RunReplaySpec(run=item["run"], report=item["report"], tasks=tuple(tasks)))
    return tuple(runs)


def _events(evidence_path: str | Path) -> list[dict[str, Any]] | None:
    """Read a journal, or return ``None`` when it is not independently usable."""
    try:
        events = [
            json.loads(line)
            for line in Path(evidence_path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not events or any(not isinstance(event, dict) for event in events):
        return None
    sequences = [event.get("sequence") for event in events]
    if sequences != list(range(1, len(events) + 1)):
        return None
    if events[-1].get("event_type") != "loop.finished":
        return None
    return events


def _committed_digests(events: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    digests = set()
    for event in events:
        for key in ("observed_digest", "output_digest"):
            value = event.get(key)
            if isinstance(value, str) and len(value) == 71 and value.startswith(_DIGEST_PREFIX):
                digests.add(value.lower())
    return frozenset(digests)


def _plan_manifest(events: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    for event in events:
        if event.get("event_type") != "plan.admitted":
            continue
        manifest = event.get("plan_step_manifest")
        if not isinstance(manifest, list):
            continue
        mapping = {}
        for item in manifest:
            if isinstance(item, dict) and isinstance(item.get("step_id"), str):
                mapping[item["step_id"]] = str(item.get("execution_id") or "")
        return mapping
    return {}


def observed_milestones(
    events: Sequence[Mapping[str, Any]], labels: Sequence[str]
) -> tuple[str, ...]:
    """Derive the committed milestone order from the journal, never from prose."""
    manifest = _plan_manifest(events)
    observed: list[str] = []
    for event in events:
        if event.get("event_type") != "step.observed":
            continue
        if event.get("status") != "verified_committed":
            continue
        step_id = str(event.get("step_id") or "")
        haystack = f"{manifest.get(step_id, '')} {step_id}".lower()
        for label in labels:
            if label.lower() in haystack:
                if not observed or observed[-1] != label:
                    observed.append(label)
                break
    return tuple(observed)


def _snapshot(files: Mapping[str, str]) -> WorkspaceSnapshot:
    return WorkspaceSnapshot.from_files(dict(files))


def observe_archived_workspace(
    context: HostReplayContext,
    run: RunReplaySpec,
    spec: TaskReplaySpec,
    dest: str | Path,
) -> tuple[WorkspaceSnapshot, WorkspaceSnapshot]:
    """Observe the archived workspace the way a live run would be observed.

    Seed files are materialized first, the deliverable is written, and the same
    root is observed again. The contract then sees host observation of real
    directory state rather than caller-supplied text.
    """
    run_root = context.archive_root / run.run
    fixture = json.loads((run_root / spec.fixture).read_text(encoding="utf-8"))
    seed = {
        name: value
        for name, value in (fixture.get("seed") or {}).items()
        if isinstance(value, str)
    }
    root = materialize_workspace(dest, seed)
    before = observe_workspace(root)
    for path, archived in sorted(spec.artifacts.items()):
        content = (run_root / archived).read_text(encoding="utf-8")
        materialize_workspace(root, {path: content})
    after = observe_workspace(root)
    return before, after


def _build_contract(
    *,
    mode: str,
    spec: TaskReplaySpec,
    artifact_digests: Mapping[str, str],
    provenance: Provenance,
) -> CompletionContractV2:
    expectations = []
    for path, requirement in sorted(spec.artifacts.items()):
        if mode == "digest":
            expectations.append(ArtifactExpectation(path=path, exact_digest=artifact_digests[path]))
        else:
            fields = spec.semantic_fields.get(path)
            if not fields:
                raise ValueError(f"semantic mode needs declared fields for {path}")
            expectations.append(
                ArtifactExpectation(
                    path=path,
                    semantic_fields=tuple(
                        SemanticField(
                            name=field.name,
                            expected_value=field.expected_value,
                            mode=field.mode,
                        )
                        for field in fields
                    ),
                )
            )
    return CompletionContractV2(
        required_artifacts=tuple(expectations),
        allowed_mutations=tuple(sorted(spec.artifacts)),
        required_milestones=spec.milestone_labels,
        milestone_edges=spec.milestone_edges,
        expected_provenance=provenance,
    )


def replay_archive_task(
    context: HostReplayContext,
    run: RunReplaySpec,
    spec: TaskReplaySpec,
    *,
    mode: str,
    observed_root: Path | None = None,
) -> TaskReplayOutcome:
    """Replay one archived task in one mode. Fail closed on any missing ground truth."""
    if mode not in _MODES:
        raise ValueError("replay mode is invalid")
    run_root = context.archive_root / run.run
    evidence_path = run_root / spec.evidence
    events = _events(evidence_path)
    if events is None:
        return TaskReplayOutcome(
            run.run, spec.task_id, mode, "unknown",
            ("evidence_terminal_state_unavailable",), False, (), 0,
        )
    committed = _committed_digests(events)
    fixture_path = run_root / spec.fixture
    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return TaskReplayOutcome(
            run.run, spec.task_id, mode, "insufficient_information",
            ("fixture_unreadable",), False, (), 0,
        )

    contents: dict[str, str] = {}
    digests: dict[str, str] = {}
    for path, archived in sorted(spec.artifacts.items()):
        try:
            raw = (run_root / archived).read_bytes()
        except OSError:
            return TaskReplayOutcome(
                run.run, spec.task_id, mode, "insufficient_information",
                ("archived_artifact_missing",), False, (), 0,
            )
        digest = _sha256(raw)
        if digest not in committed:
            return TaskReplayOutcome(
                run.run, spec.task_id, mode, "insufficient_information",
                ("artifact_not_bound_to_final_evidence",), False, (), 0,
            )
        try:
            contents[path] = raw.decode("utf-8")
        except UnicodeDecodeError:
            return TaskReplayOutcome(
                run.run, spec.task_id, mode, "insufficient_information",
                ("archived_artifact_not_text",), False, (), 0,
            )
        digests[path] = digest

    if mode == "semantic":
        undeclared = [path for path in sorted(spec.artifacts) if not spec.semantic_fields.get(path)]
        if undeclared:
            return TaskReplayOutcome(
                run.run, spec.task_id, mode, "insufficient_information",
                ("semantic_fields_undeclared:" + ",".join(undeclared),), True, (), 0,
            )

    config = ReplayConfig(
        evaluator_path=context.evaluator_path,
        fixture_path=fixture_path,
        benchmark_commit=context.benchmark_commit,
        environment_digest=context.environment_digest,
        model_id=context.model_id,
        model_revision=context.model_revision,
        reasoning_effort=context.reasoning_effort,
        max_output_tokens=context.max_output_tokens,
        seed=context.run_seed,
        trial_id=f"{run.run}:{spec.task_id}",
    )
    provenance = config.provenance()
    contract = _build_contract(
        mode=mode,
        spec=spec,
        artifact_digests=digests,
        provenance=provenance,
    )
    seed = fixture.get("seed") or {}
    if not isinstance(seed, dict):
        return TaskReplayOutcome(
            run.run, spec.task_id, mode, "insufficient_information",
            ("fixture_seed_invalid",), False, (), 0,
        )
    if observed_root is None:
        before = _snapshot({name: value for name, value in seed.items() if isinstance(value, str)})
        after = _snapshot({**seed, **contents})
    else:
        before, after = observe_archived_workspace(context, run, spec, observed_root)
    milestones = observed_milestones(events, spec.milestone_labels)
    result = replay_task_report(
        run_root / run.report,
        evidence_path,
        task_id=spec.task_id,
        contract=contract,
        before=before,
        after=after,
        milestones=milestones,
        provenance=provenance,
    )
    declared = sum(len(fields) for fields in spec.semantic_fields.values()) if mode == "semantic" else 0
    return TaskReplayOutcome(
        run.run, spec.task_id, mode, result.verdict, tuple(result.errors), True, milestones, declared,
    )


def replay_archive(
    context: HostReplayContext,
    specs: Sequence[RunReplaySpec],
    *,
    modes: Sequence[str] = _MODES,
    observed_root: Path | None = None,
) -> tuple[TaskReplayOutcome, ...]:
    outcomes = []
    for run in specs:
        for spec in run.tasks:
            dest = None
            if observed_root is not None:
                dest = observed_root / run.run / spec.task_id
            for mode in modes:
                outcomes.append(
                    replay_archive_task(context, run, spec, mode=mode, observed_root=dest)
                )
    return tuple(outcomes)


def summarize(outcomes: Sequence[TaskReplayOutcome]) -> dict[str, Any]:
    """Aggregate verdicts per mode, and name every non-verified task explicitly."""
    summary: dict[str, Any] = {"total": len(outcomes), "modes": {}}
    for mode in sorted({outcome.mode for outcome in outcomes}):
        selected = [outcome for outcome in outcomes if outcome.mode == mode]
        counts = Counter(outcome.verdict for outcome in selected)
        summary["modes"][mode] = {
            "counts": dict(sorted(counts.items())),
            "non_verified": [
                {
                    "run": outcome.run,
                    "task_id": outcome.task_id,
                    "verdict": outcome.verdict,
                    "errors": list(outcome.errors),
                    "milestones": list(outcome.milestones),
                    "declared_fields": outcome.declared_fields,
                }
                for outcome in selected
                if outcome.verdict != "verified"
            ],
            "artifact_bound": sum(1 for outcome in selected if outcome.artifact_bound),
        }
    return summary


def default_context(archive_root: Path, evaluator_path: Path) -> HostReplayContext:
    return HostReplayContext(
        archive_root=archive_root,
        evaluator_path=evaluator_path,
        benchmark_commit="archive-replay",
        environment_digest=_DIGEST_PREFIX + "0" * 64,
        model_id="archived-run",
        model_revision="archived-run",
        reasoning_effort="off",
        max_output_tokens=_REPLAY_ENVELOPE_MAX_OUTPUT_TOKENS,
        run_seed="archive-replay",
    )


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Replay archived Northstar runs.")
    parser.add_argument("--archive-root", default="/var/minis/shared/northstar-live-runs")
    parser.add_argument("--spec", default=str(Path(__file__).with_name("replay") / "archive-replay-spec.json"))
    parser.add_argument("--json-out")
    parser.add_argument(
        "--observe",
        action="store_true",
        help="materialize and observe archived workspaces instead of caller-built snapshots",
    )
    arguments = parser.parse_args(argv)

    specs = load_spec(arguments.spec)
    context = default_context(
        Path(arguments.archive_root), Path(__file__).resolve().parent / "completion_contract_v2.py"
    )
    observed_root = None
    if arguments.observe:
        import tempfile

        observed_root = Path(tempfile.mkdtemp(prefix="northstar-replay-observed-"))
    outcomes = replay_archive(context, specs, observed_root=observed_root)
    summary = summarize(outcomes)
    for mode, data in summary["modes"].items():
        print(f"[{mode}] {data['counts']}")
        for item in data["non_verified"]:
            print(f"    {item['run']} {item['task_id']} -> {item['verdict']} {item['errors']}")
    if arguments.json_out:
        Path(arguments.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"note: {PROVENANCE_SCOPE_NOTE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
