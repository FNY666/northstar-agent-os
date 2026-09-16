"""Read-only layered completion advisory for real production runs.

The production gate decides ``TaskOutcome.ok``. This module computes a second,
non-authorizing opinion next to it and never feeds back: the advisory is attached
to the run report as data, carries ``execution_authorized: false`` and
``affects_task_outcome: false``, and is deliberately not consulted by the
driver, the verifier, or the process exit code.

Why attach it at all: the four-sample live shadow corpus showed the production
gate accepts content a semantic contract rejects (a negated claim, an extra
unapproved file) while both gates agree on normal completion and on recovery
from a transient execution failure. Recording the layered verdict beside the
real run is the cheapest way to collect that difference distribution on real
traffic before anyone considers making it authoritative.

Two deliberate reuse decisions keep this honest:

* production-gate semantics come from
  ``completion_live_shadow.production_result_from_host_check``, so the advisory
  cannot drift from the harness shadow on how cancelled or unfinished runs count;
* the host-owned shadow contract spec is parsed by ``contract_from_spec`` here
  and imported by the live shadow runner, so one definition covers both.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from completion_contract_v2 import (
    ArtifactExpectation,
    CompletionContractV2,
    CompletionResult,
    Provenance,
    SemanticField,
    WorkspaceSnapshot,
)
from completion_live_shadow import production_result_from_host_check
from completion_replay import _evidence_status
from completion_shadow import LayeredVerificationResult, compose_shadow
from verifier import VerificationResult

_DIGEST_PREFIX = "sha256:"


def contract_from_spec(spec: dict[str, Any], provenance: Provenance) -> CompletionContractV2:
    """Build the host-owned shadow contract declared by a fixture.

    Only the artifact paths listed in the spec may be mutated, so an extra file
    written by the actor is a contract failure rather than an unnoticed change.
    """
    artifacts = []
    for item in spec["artifacts"]:
        fields = tuple(
            SemanticField(field["name"], field["value"], field.get("mode", "contains"))
            for field in item["semantic_fields"]
        )
        artifacts.append(ArtifactExpectation(item["path"], semantic_fields=fields))
    return CompletionContractV2(
        required_artifacts=tuple(artifacts),
        allowed_mutations=tuple(item["path"] for item in spec["artifacts"]),
        required_milestones=tuple(spec["milestones"]),
        milestone_edges=tuple(tuple(edge) for edge in spec.get("milestone_edges", [])),
        expected_provenance=provenance,
    )


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def file_digest(path: str | Path) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _git_head() -> str:
    """Read the benchmark commit without leaking a pipe if git is unavailable."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "0" * 40
    head = result.stdout.strip()
    return head or "0" * 40


def provenance_from(
    *,
    contract_revision: str,
    fixture_path: str | Path,
    evaluator_path: str | Path,
    model_id: str,
    model_revision: str,
    reasoning_effort: str,
    max_output_tokens: int,
    seed: str,
    trial_id: str,
) -> Provenance:
    """Build the host-owned provenance envelope for one observed run.

    Digests are computed here from the actual files rather than copied from the
    report, so a fixture or evaluator edit cannot leave a stale label behind.
    """
    commit = _git_head()
    return Provenance.from_dict(
        {
            "contract_revision": contract_revision,
            "evaluator_digest": file_digest(evaluator_path),
            "fixture_digest": file_digest(fixture_path),
            "benchmark_commit": commit,
            "environment_digest": "sha256:" + hashlib.sha256(sys.version.encode()).hexdigest(),
            "model_id": model_id,
            "model_revision": model_revision,
            "reasoning_effort": reasoning_effort,
            "max_output_tokens": max_output_tokens,
            "seed": seed,
            "trial_id": trial_id,
        }
    )


@dataclass(frozen=True)
class DriverAdvisory:
    """A layered opinion recorded beside a real run, never an authorization."""

    production: VerificationResult
    contract: CompletionResult
    layered: LayeredVerificationResult
    evidence_path: Path

    def as_report_dict(self) -> dict[str, Any]:
        if self.layered.execution_authorized:
            raise AssertionError("completion advisory must never authorize execution")
        payload: dict[str, Any] = {
            "schema_version": "northstar.completion-advisory.v1",
            "authoritative": False,
            "affects_task_outcome": False,
            "execution_authorized": False,
            "production_verdict": self.production.verdict,
            "contract_verdict": self.contract.verdict,
            "layered_verdict": self.layered.verdict,
            "layered_errors": list(self.layered.errors),
            "contract_errors": list(self.contract.errors),
            "observed_digests": dict(sorted(self.production.artifact_digests.items())),
            "evidence_journal": str(self.evidence_path),
        }
        payload["advisory_digest"] = _digest(payload)
        return payload


def evaluate_driver_advisory(
    *,
    contract: CompletionContractV2,
    provenance: Provenance,
    verification: Any,
    run_status: str,
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
    evidence_path: str | Path,
    milestones: tuple[str, ...] | None = None,
    milestone_action_map: dict[str, str] | None = None,
    round_steps: tuple[dict[str, Any], ...] | list[dict[str, Any]] = (),
) -> DriverAdvisory:
    """Compute the layered advisory for one finished production run.

    ``verification`` is the driver's own host check; its verdict is only ever
    re-expressed, never trusted as a boolean. ``evidence_path`` must be the
    journal of the round that produced the final deliverable -- the terminal
    state of an earlier round says nothing about the current one.
    """
    if not isinstance(contract, CompletionContractV2):
        raise ValueError("contract must be CompletionContractV2")
    if not isinstance(provenance, Provenance):
        raise ValueError("provenance must be Provenance")
    journal = Path(evidence_path)
    production = production_result_from_host_check(
        verdict=verification.verdict,
        failures=verification.failures,
        checked=verification.checked,
        run_status=run_status,
        after=after,
    )
    if milestones is None and milestone_action_map is not None:
        milestones = tuple(
            milestone_action_map[step["action_id"]]
            for step in round_steps
            if step.get("action_id") in milestone_action_map
        )
    status = _evidence_status(journal)
    if not status:
        contract_result = CompletionResult(
            "unknown", ("evidence_terminal_state_unavailable",), ()
        )
    else:
        contract_result = contract.evaluate(
            before=before,
            after=after,
            milestones=milestones,
            provenance=provenance,
            run_status=status,
        )
    return DriverAdvisory(
        production=production,
        contract=contract_result,
        layered=compose_shadow(production, contract_result),
        evidence_path=journal,
    )
