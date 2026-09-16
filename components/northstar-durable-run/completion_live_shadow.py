"""Test-only shadow adapter for a real AgentHarness run.

The adapter observes the real workspace before and after the harness runs, uses
the harness's production verification result as one gate, independently reads
the host evidence journal as the other, and composes them without changing the
returned TaskOutcome or authorizing any action.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from completion_contract_v2 import (
    CompletionContractV2,
    CompletionResult,
    Provenance,
    WorkspaceSnapshot,
)
from completion_replay import _evidence_status
from completion_shadow import LayeredVerificationResult, compose_shadow
from completion_workspace_snapshot import WorkspaceObservationRefused, observe_workspace
from verifier import VerificationResult


@dataclass(frozen=True)
class LiveShadowResult:
    task_outcome: Any
    production: VerificationResult
    contract: CompletionResult
    layered: LayeredVerificationResult
    before: WorkspaceSnapshot
    after: WorkspaceSnapshot


def production_result_from_host_check(
    *,
    verdict: str,
    failures: tuple[str, ...] | list[str],
    checked: tuple[str, ...] | list[str],
    run_status: str,
    after: WorkspaceSnapshot,
) -> VerificationResult:
    """Adapt a host check without trusting its boolean summary.

    This is the single definition of how the production gate's own result is
    re-expressed for shadow comparison: a cancelled run is a failure, any run
    that is not finished is unknown, and only a finished run passes its verdict
    through. Both the harness shadow adapter and the production advisory reuse
    it so the two paths cannot drift.
    """
    digests = {path: after.files[path].digest for path in checked if path in after.files}
    if run_status == "cancelled":
        return VerificationResult("failed", ("run was cancelled",), digests)
    if run_status != "finished":
        return VerificationResult(
            "unknown",
            (f"run is not finished: {run_status}",),
            digests,
        )
    return VerificationResult(verdict, tuple(failures), digests)


def _production_result(task_outcome: Any, after: WorkspaceSnapshot) -> VerificationResult:
    """Adapt the harness-owned host check without trusting its boolean summary."""
    verification = task_outcome.verification
    return production_result_from_host_check(
        verdict=verification.verdict,
        failures=verification.failures,
        checked=verification.checked,
        run_status=task_outcome.run_status,
        after=after,
    )


def _unknown_contract(error: str) -> CompletionResult:
    return CompletionResult("unknown", (error,), ())


def run_live_shadow(
    harness: Any,
    goal: str,
    planner: Any,
    *,
    contract: CompletionContractV2,
    expectations: list[Any] | tuple[Any, ...],
    provenance: Provenance,
    milestones: tuple[str, ...] | None = None,
    milestone_action_map: dict[str, str] | None = None,
    evidence_path: str | Path | None = None,
) -> LiveShadowResult:
    """Run one real harness goal and calculate a non-authorizing shadow result."""
    if not isinstance(contract, CompletionContractV2):
        raise ValueError("contract must be CompletionContractV2")
    if not isinstance(provenance, Provenance):
        raise ValueError("provenance must be Provenance")
    before = observe_workspace(harness.workspace_root)
    task_outcome = harness.run_goal(goal, planner, expectations=expectations)
    after = observe_workspace(harness.workspace_root)
    production = _production_result(task_outcome, after)
    if milestones is None and milestone_action_map is not None:
        milestones = tuple(
            milestone_action_map[step.action_id]
            for step in task_outcome.steps
            if step.action_id in milestone_action_map
        )
    journal = Path(evidence_path) if evidence_path is not None else harness.evidence_path
    status = _evidence_status(journal)
    if not status:
        contract_result = _unknown_contract("evidence_terminal_state_unavailable")
    else:
        contract_result = contract.evaluate(
            before=before,
            after=after,
            milestones=milestones,
            provenance=provenance,
            run_status=status,
        )
    layered = compose_shadow(production, contract_result)
    return LiveShadowResult(
        task_outcome=task_outcome,
        production=production,
        contract=contract_result,
        layered=layered,
        before=before,
        after=after,
    )
