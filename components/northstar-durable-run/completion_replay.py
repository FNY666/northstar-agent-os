"""Test-only adapter from Northstar reports/evidence to Completion Contract v2."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from completion_contract_v2 import (
    CompletionContractV2,
    CompletionResult,
    Provenance,
    WorkspaceSnapshot,
)


def _sha256_file(path: str | Path) -> str:
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValueError("provenance source could not be read") from error
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ReplayConfig:
    evaluator_path: str | Path
    fixture_path: str | Path
    benchmark_commit: str
    environment_digest: str
    model_id: str
    model_revision: str
    reasoning_effort: str
    max_output_tokens: int
    seed: str
    trial_id: str
    contract_revision: str = "completion-v2-replay-1"

    def provenance(self) -> Provenance:
        return Provenance.from_dict(
            {
                "contract_revision": self.contract_revision,
                "evaluator_digest": _sha256_file(self.evaluator_path),
                "fixture_digest": _sha256_file(self.fixture_path),
                "benchmark_commit": self.benchmark_commit,
                "environment_digest": self.environment_digest,
                "model_id": self.model_id,
                "model_revision": self.model_revision,
                "reasoning_effort": self.reasoning_effort,
                "max_output_tokens": self.max_output_tokens,
                "seed": self.seed,
                "trial_id": self.trial_id,
            }
        )


def _load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _task(report: Any, task_id: str) -> dict[str, Any] | None:
    if not isinstance(report, dict) or not isinstance(report.get("tasks"), list):
        return None
    matches = [item for item in report["tasks"] if isinstance(item, dict) and item.get("task_id") == task_id]
    return matches[0] if len(matches) == 1 else None


def _evidence_status(path: str | Path) -> str:
    """Return an independently derived terminal status, or empty on uncertainty."""
    try:
        events = [
            json.loads(line)
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not events or any(not isinstance(event, dict) for event in events):
        return ""
    sequences = [event.get("sequence") for event in events]
    if sequences != list(range(1, len(events) + 1)):
        return ""
    if events[-1].get("event_type") != "loop.finished":
        return ""
    return "finished"


def replay_task_report(
    report_path: str | Path,
    evidence_path: str | Path,
    *,
    task_id: str,
    contract: CompletionContractV2,
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
    milestones: tuple[str, ...] | None,
    provenance: Provenance | None = None,
) -> CompletionResult:
    """Replay one task through the test-only contract.

    Report provenance is host-supplied input. The report's ``ok`` and
    ``verification`` fields are intentionally ignored. Evidence supplies only
    independently checked terminal state; artifact correctness comes from the
    caller's independent snapshots.
    """
    if not isinstance(contract, CompletionContractV2):
        raise ValueError("contract must be CompletionContractV2")
    report = _load_json(report_path)
    task = _task(report, task_id)
    if task is None:
        return CompletionResult("insufficient_information", ("task_report_missing",), ())
    if provenance is None:
        raw_provenance = task.get("provenance")
        if raw_provenance is None:
            return CompletionResult("insufficient_information", ("provenance_missing",), ())
        try:
            provenance = Provenance.from_dict(raw_provenance)
        except ValueError:
            return CompletionResult("insufficient_information", ("provenance_invalid",), ())
    run_status = _evidence_status(evidence_path)
    if not run_status:
        return CompletionResult("unknown", ("evidence_terminal_state_unavailable",), ())
    return contract.evaluate(
        before=before,
        after=after,
        milestones=milestones,
        provenance=provenance,
        run_status=run_status,
    )
