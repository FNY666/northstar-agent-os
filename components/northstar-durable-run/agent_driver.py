"""Bounded plan → execute → observe → re-plan driver.

A single admitted plan is static, and a static plan cannot produce a
data-dependent deliverable: the model must fix `content` before anything has
been read. The driver closes that loop while keeping every existing boundary:

* each round is a separate governed run (own run id, own authorization grant,
  own evidence stream), so rounds cannot smuggle state through the loop;
* observations are collected by the host from the filesystem, never from a
  tool's claimed output;
* the model sees only bounded observations, and the deliverable is still
  verified by the host against host-owned expectations;
* the number of rounds and the size of every observation are bounded, so a
  confused model cannot spend without limit or flood its own context.

It is deliberately not a general agent: no re-planning after a refused action,
no tool discovery, no sub-agents, and no memory across tasks.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agent_entry import AgentHarness, DeliverableVerification, ExpectedArtifact, build_run

DEFAULT_MAX_ROUNDS = 3
DEFAULT_MAX_OBSERVED_FILES = 12
DEFAULT_MAX_OBSERVATION_BYTES = 2_048


@dataclass(frozen=True)
class DriverBudget:
    max_rounds: int = DEFAULT_MAX_ROUNDS
    max_observed_files: int = DEFAULT_MAX_OBSERVED_FILES
    max_observation_bytes: int = DEFAULT_MAX_OBSERVATION_BYTES
    deadline_seconds_per_round: int = 120

    def __post_init__(self) -> None:
        if not 1 <= self.max_rounds <= 8:
            raise ValueError("max_rounds must be between 1 and 8")
        if not 1 <= self.max_observed_files <= 64:
            raise ValueError("max_observed_files must be between 1 and 64")
        if not 1 <= self.max_observation_bytes <= 32_768:
            raise ValueError("max_observation_bytes is invalid")
        if not 1 <= self.deadline_seconds_per_round <= 3_600:
            raise ValueError("deadline_seconds_per_round is invalid")


@dataclass(frozen=True)
class RoundRecord:
    round_index: int
    run_id: str
    status: str
    planner_attempts: int
    resumes: int
    steps: tuple[dict[str, Any], ...]
    observed: tuple[str, ...]
    error: str | None
    blocked: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "round": self.round_index,
            "run_id": self.run_id,
            "status": self.status,
            "planner_attempts": self.planner_attempts,
            "resumes": self.resumes,
            "steps": list(self.steps),
            "observed": list(self.observed),
            "error": self.error,
            "blocked": self.blocked,
        }


@dataclass(frozen=True)
class DriverOutcome:
    task_id: str
    goal: str
    rounds: tuple[RoundRecord, ...]
    verification: DeliverableVerification
    observations: dict[str, dict[str, Any]]

    @property
    def ok(self) -> bool:
        """Only a host-verified deliverable counts, and only after a finished round."""
        finished = any(record.status == "finished" for record in self.rounds)
        return finished and self.verification.verdict == "verified"

    @property
    def model_calls(self) -> int:
        return sum(record.planner_attempts for record in self.rounds)

    @property
    def resumes(self) -> int:
        return sum(record.resumes for record in self.rounds)

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "goal": self.goal,
            "ok": self.ok,
            "round_count": len(self.rounds),
            "model_calls": self.model_calls,
            "resumes": self.resumes,
            "verification": self.verification.as_dict(),
            "rounds": [record.as_dict() for record in self.rounds],
            "observations": sorted(self.observations),
        }


# A round that hit one of these is a real stop: neither governance refusals nor
# a pending human approval may be re-planned around.
_BLOCKING_EVENTS = {"step.action_denied", "step.awaiting_approval"}


def _round_blocked(evidence_path: Path) -> str | None:
    if not evidence_path.exists():
        return None
    try:
        lines = evidence_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "evidence_unreadable"
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return "evidence_invalid"
        if event.get("event_type") in _BLOCKING_EVENTS:
            return str(event.get("event_type"))
    return None


class AgentDriver:
    """Run one goal across bounded rounds until the host check passes."""

    def __init__(
        self,
        *,
        workspace_root: str | Path,
        evidence_dir: str | Path,
        actor_id: str = "actor-agent-001",
        workspace_id: str = "workspace-agent-001",
        policy_revision: str = "policy-agent-1",
        expectations: tuple[ExpectedArtifact, ...] | list[ExpectedArtifact] = (),
        budget: DriverBudget | None = None,
        clock: Callable[[], int] | None = None,
        allowed_write_paths=None,
        allowed_read_paths=None,
        harness_builder: Callable[..., AgentHarness] | None = None,
    ):
        self.workspace_root = Path(os.path.realpath(workspace_root))
        if not self.workspace_root.is_dir():
            raise ValueError("workspace root must be an existing directory")
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.actor_id = actor_id
        self.workspace_id = workspace_id
        self.policy_revision = policy_revision
        self.expectations = tuple(expectations)
        self.budget = budget or DriverBudget()
        self.clock = clock
        self.allowed_write_paths = allowed_write_paths
        self.allowed_read_paths = allowed_read_paths
        self._harness_builder = harness_builder or self._default_harness

    # ------------------------------------------------------------------ host

    def _default_harness(self, run, evidence_path: Path) -> AgentHarness:
        return AgentHarness(
            run,
            self.workspace_root,
            evidence_path,
            actor_id=self.actor_id,
            workspace_id=self.workspace_id,
            policy_revision=self.policy_revision,
            clock=self.clock,
            allowed_read_paths=self.allowed_read_paths,
            allowed_write_paths=self.allowed_write_paths,
        )

    def _harness(self, task_id: str, round_index: int) -> AgentHarness:
        run = build_run(
            f"{task_id}-r{round_index}",
            clock=self.clock,
            deadline_seconds=self.budget.deadline_seconds_per_round,
        )
        evidence_path = self.evidence_dir / f"round-{round_index}.evidence.jsonl"
        if evidence_path.exists():
            # Reusing a round's evidence file mixes two runs into one history:
            # the loop then rejects the new plan digest against the old events.
            # Refuse loudly instead of producing a confusing digest mismatch.
            raise ValueError(f"evidence for round {round_index} already exists")
        return self._harness_builder(run, evidence_path)

    def _observe(self, harness: AgentHarness) -> dict[str, dict[str, Any]]:
        collected: dict[str, dict[str, Any]] = {}
        for step in harness.admitted_steps():
            payload = step.input_payload
            if step.action_id == "workspace.list":
                prefix = payload.get("prefix", "")
                observation = harness.inspect_listing(
                    prefix,
                    max_depth=payload.get("max_depth"),
                    max_entries=payload.get("max_entries"),
                )
                observation["action_id"] = step.action_id
                collected[f"listing:{prefix or '.'}"] = observation
                continue
            path = payload.get("path")
            if not isinstance(path, str):
                continue
            observation = harness.inspect(path, limit=self.budget.max_observation_bytes)
            observation["action_id"] = step.action_id
            if step.action_id == "workspace.write":
                # A write is the agent's own output; keep its digest, not a copy
                # of its content, so a round cannot be steered by stale text.
                observation.pop("content", None)
            collected[path] = observation
        return collected

    def run(self, task_id: str, goal: str, planner) -> DriverOutcome:
        """Rounds are bounded; only proven-absent rounds may be re-planned."""
        observations: dict[str, dict[str, Any]] = {}
        rounds: list[RoundRecord] = []
        verification = DeliverableVerification("unknown", (), ("not_run",))
        for round_index in range(1, self.budget.max_rounds + 1):
            harness = self._harness(task_id, round_index)
            extra = {
                "round": round_index,
                "rounds_remaining": self.budget.max_rounds - round_index,
                "observations": observations,
                "verification_feedback": list(verification.failures),
            }
            try:
                outcome = harness.run_goal(goal, planner, context=extra)
            except Exception as error:
                # Planning, admission, or the round itself failed before any
                # step could run. Record the failure kind and stop: retrying a
                # rejection blindly is not recovery.
                rounds.append(
                    RoundRecord(
                        round_index, harness.run.run_id, "round_failed", 0, 0, (), (), type(error).__name__
                    )
                )
                break
            fresh = self._observe(harness)
            for path, value in sorted(fresh.items()):
                if path in observations or len(observations) < self.budget.max_observed_files:
                    observations[path] = value
            blocked = _round_blocked(self.evidence_dir / f"round-{round_index}.evidence.jsonl")
            rounds.append(
                RoundRecord(
                    round_index,
                    harness.run.run_id,
                    outcome.run_status,
                    outcome.planner_attempts,
                    outcome.resumes,
                    tuple(step.as_dict() for step in outcome.steps),
                    tuple(sorted(fresh)),
                    None,
                    blocked,
                )
            )
            verification = harness.verify_expectations(self.expectations)
            if verification.verdict == "verified":
                break
            if blocked is not None:
                # Refused or awaiting a human: re-planning around it would be
                # exactly the behaviour this system exists to prevent.
                break
            if outcome.run_status == "paused_unknown":
                # The world is uncertain, not proven absent; stop and say so.
                break
        return DriverOutcome(
            task_id=task_id,
            goal=goal,
            rounds=tuple(rounds),
            verification=verification,
            observations=observations,
        )



def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the bounded re-planning driver from a step file.")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--goal", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--rounds", type=int, default=DEFAULT_MAX_ROUNDS)
    parser.add_argument("--expect", default=None)
    arguments = parser.parse_args(argv)
    expects = []
    if arguments.expect:
        expects = [
            ExpectedArtifact(
                path=item["path"],
                content=item.get("content"),
                digest=item.get("digest"),
                absent=bool(item.get("absent", False)),
                contains=tuple(item["contains"]) if item.get("contains") else None,
            )
            for item in json.loads(Path(arguments.expect).read_text(encoding="utf-8"))
        ]
    driver = AgentDriver(
        workspace_root=arguments.workspace,
        evidence_dir=Path(arguments.workspace) / "evidence",
        expectations=expects,
        budget=DriverBudget(max_rounds=arguments.rounds),
    )
    print(json.dumps({"driver": "ready", "workspace": driver.workspace_root.name, "expect": len(expects)}, indent=2))
    return 0
