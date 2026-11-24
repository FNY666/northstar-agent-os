"""Resume an interrupted ``northstar code`` run from its durable evidence.

A ``northstar code`` run keeps every phase transition and every tool-effect
receipt in ``phases.json``.  When a run is interrupted, the evidence directory
is preserved together with the isolated worktree, so the run can be continued
instead of restarted.

This module provides the resume path:

* :func:`prepare_code_resume` — decide whether an interrupted run may be
  continued, without mutating anything.
* :func:`restore_phase_machine` — rebuild the phase gate from the durable
  journal so the resumed run continues under the same phase protocol.
* :func:`resume_code_run` — continue the run inside the *same* worktree, from
  the *same* starting commit, forking from the parent session's checkpoint.

Safety rules this module must not weaken:

* An effect without a completion receipt (``in_flight`` or ``unknown``) means
  the runtime lost track of a side effect.  Resuming would replay that effect,
  so a resume is refused and the operator is pointed at
  ``reconcile_code_evidence``.
* A terminal run is never resumed.
* The resumed run reuses the recorded worktree and starting commit, so the
  delivered patch still replays from the original commit.
* The resumed run refuses to change the declared checks or the pinned check
  inputs, so a resume cannot quietly weaken the verification it inherits.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

from code_task import (
    CODE_PHASE_TERMINALS,
    CodePhaseMachine,
    CodeRunReport,
    CodeTask,
    CodeTaskError,
    _atomic_write,
    _read_evidence_json,
    reconcile_code_evidence,
    validate_check_inputs,
)

RESUMABLE_PHASES = frozenset({"understanding", "planned", "executing", "verifying"})

RESUME_RECEIPT_SCHEMA = "northstar.code-resume.v1"


# --------------------------------------------------------------------------
# Journal restore
# --------------------------------------------------------------------------
def restore_phase_machine(
    evidence_dir: str | Path,
    *,
    worktree: str | Path | None = None,
    start_commit: str = "",
) -> CodePhaseMachine:
    """Rebuild a :class:`CodePhaseMachine` from a durable phase journal.

    The journal is the source of truth: the restored machine carries the same
    run id, plan, effect receipts and transitions that were durably recorded.
    Nothing is inferred from the current worktree contents, because the worktree
    may have been left in any state by an interrupted process.
    """
    root = Path(evidence_dir).expanduser().resolve()
    phases, _raw = _read_evidence_json(root, "phases.json")
    if phases.get("schema") != "northstar.code-phases.v1":
        raise CodeTaskError("unsupported phase schema")
    run_id = str(phases.get("run_id") or "")
    if not run_id:
        raise CodeTaskError("phase journal has no run id")
    state = str(phases.get("state") or "")
    outcome = phases.get("outcome")
    if outcome is not None:
        raise CodeTaskError("a terminal code run cannot be resumed")
    if state not in RESUMABLE_PHASES:
        raise CodeTaskError(f"phase journal is not resumable: {state or '(empty)'}")

    machine = CodePhaseMachine.restore(
        root,
        run_id=run_id,
        worktree=worktree,
        start_commit=start_commit,
    )
    with machine._lock:  # noqa: SLF001 - deliberate: same component, same invariants
        machine._state = state  # noqa: SLF001
        machine._outcome = None  # noqa: SLF001
        plan = phases.get("plan")
        machine._plan = dict(plan) if isinstance(plan, dict) else None  # noqa: SLF001
        transitions = phases.get("transitions")
        machine._transitions = (  # noqa: SLF001
            [dict(item) for item in transitions if isinstance(item, dict)]
            if isinstance(transitions, list)
            else []
        )
        pins = phases.get("check_input_pins")
        machine._check_input_pins = (  # noqa: SLF001
            tuple(dict(item) for item in pins if isinstance(item, dict))
            if isinstance(pins, list) and pins
            else None
        )
        # The effects are left exactly as ``restore`` closed them: an effect a
        # crash left open is already accounted for, and overwriting them here
        # would silently reopen it.
        machine._persist()  # noqa: SLF001
    return machine


# --------------------------------------------------------------------------
# Resume decision
# --------------------------------------------------------------------------
def prepare_code_resume(evidence_dir: str | Path) -> dict[str, Any]:
    """Decide whether an interrupted code run may be resumed.

    Returns a report describing the recorded phase, the effects that must not
    be replayed, and the session that a resume would continue.  The report never
    mutates the evidence directory beyond the reconcile receipt that
    ``reconcile_code_evidence`` itself writes.
    """
    root = Path(evidence_dir).expanduser().resolve()
    if not root.is_dir():
        raise CodeTaskError(f"code evidence directory does not exist: {root}")

    manifest, _raw = _read_evidence_json(root, "manifest.json")
    phases, _phase_raw = _read_evidence_json(root, "phases.json")

    # Integrity first: a corrupted evidence directory must not be "resumable".
    reconciliation = reconcile_code_evidence(root)
    integrity_errors = list(reconciliation.get("integrity_errors") or ())
    flagged = list(reconciliation.get("unknown_side_effects") or ())
    state = str(phases.get("state") or "")
    outcome = phases.get("outcome")

    # Only an effect *without* a completion receipt is unsafe to resume: its
    # side effect may already have happened and a resume would replay it.
    # A "failed" or "denied" effect carries a receipt, so the runtime knows
    # what happened and may continue past it.
    #
    # Host-declared checks are read-only verifications of the tree, so an
    # interrupted check is simply re-run; only an effect the *model* started
    # can have mutated the worktree and therefore must not be replayed.
    unresolved = [
        effect
        for effect in flagged
        if str(effect.get("status")) in {"in_flight", "unknown"}
        and str(effect.get("tool")) != "HostCheck"
    ]
    receipted_failures = [
        effect for effect in flagged if str(effect.get("status")) == "failed"
    ]

    # The session transcript lives beside the evidence it belongs to: the code
    # path writes it into the evidence directory's ``sessions`` subdirectory.
    session_id = ""
    sessions_dir = root / "sessions"
    if sessions_dir.is_dir():
        transcripts = sorted(sessions_dir.glob("*.jsonl"))
        if transcripts:
            session_id = transcripts[-1].stem

    worktree = str(manifest.get("worktree") or "")
    task_record = _read_evidence_json(root, "task.json")[0]
    recorded_checks = (
        tuple(str(item) for item in (task_record.get("checks") or ()))
        if isinstance(task_record, dict)
        else ()
    )
    report: dict[str, Any] = {
        "schema": RESUME_RECEIPT_SCHEMA,
        "evidence_dir": str(root),
        "run_id": str(phases.get("run_id") or ""),
        "state": state,
        "outcome": outcome,
        "plan_only": bool(phases.get("plan_only")),
        "start_commit": str(manifest.get("start_commit") or ""),
        "worktree": worktree,
        "session_id": session_id,
        "checks": list(recorded_checks),
        "unresolved_effects": unresolved,
        "receipted_failures": receipted_failures,
        "integrity_errors": integrity_errors,
        "discarded_tool_calls": 0,
        "resumable": False,
        "reason": "",
        "detail": "",
    }

    if integrity_errors:
        report.update({"reason": "evidence_integrity_failed"})
        return report
    if outcome is not None:
        report.update({"reason": "already_terminal"})
        return report
    if state not in RESUMABLE_PHASES:
        report.update({"reason": f"phase_not_resumable:{state or '(empty)'}"})
        return report
    if unresolved:
        report.update(
            {
                "reason": "unresolved_side_effects",
                "detail": (
                    "effects without a completion receipt would be replayed; "
                    "reconcile the evidence instead"
                ),
            }
        )
        return report
    if not worktree or not Path(worktree).is_dir():
        report.update({"reason": "worktree_missing"})
        return report
    if not report["start_commit"]:
        report.update({"reason": "start_commit_missing"})
        return report
    if not session_id:
        report.update(
            {
                "reason": "no_session_transcript",
                "detail": "the interrupted run left no transcript to continue from",
            }
        )
        return report

    # A resume forks the parent transcript at a checkpoint, discarding whatever
    # the parent did after it.  Any tool call in that tail may have changed the
    # worktree already, so the number of discarded calls is part of the
    # decision the operator has to see.
    try:
        from checkpoint_select import select_resume_checkpoint

        _checkpoint, discarded = select_resume_checkpoint(sessions_dir, session_id)
    except CodeTaskError as error:
        report.update({"reason": "no_resumable_checkpoint", "detail": str(error)})
        return report
    report["discarded_tool_calls"] = discarded

    report.update({"resumable": True})
    return report


def write_resume_receipt(evidence_dir: str | Path, report: dict[str, Any]) -> Path:
    """Record the resume decision inside the evidence directory."""
    root = Path(evidence_dir).expanduser().resolve()
    path = root / "resume.json"
    raw = (
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    _atomic_write(path, raw)
    return path


# --------------------------------------------------------------------------
# Resume execution
# --------------------------------------------------------------------------
def _recorded_task(root: Path) -> dict[str, Any]:
    task, _raw = _read_evidence_json(root, "task.json")
    if not isinstance(task, dict) or not task.get("goal"):
        raise CodeTaskError("the recorded task has no goal")
    return task


def resume_code_run(
    evidence_dir: str | Path,
    *,
    runner: Any = None,
    options: Any = None,
    keep_worktree: bool = True,
) -> CodeRunReport:
    """Continue an interrupted code run inside its original isolated worktree.

    The resumed run uses the recorded worktree, the recorded starting commit and
    the declared checks of the interrupted run.  It forks from the parent
    session's checkpoint, so the model continues from the context it had, and
    the parent's transcript is never modified.

    ``runner`` is called as ``runner(goal, worktree, session_id, phases)`` and
    must return an object with ``subtype``, ``exit_code`` and ``events``.  The
    CLI passes its own run path, so a resumed run goes through exactly the same
    permission, policy and provider resolution as any other run.
    """
    root = Path(evidence_dir).expanduser().resolve()
    report = prepare_code_resume(root)
    write_resume_receipt(root, report)
    if not report["resumable"]:
        raise CodeTaskError(
            f"code run cannot be resumed ({report['reason']})"
            + (f": {report['detail']}" if report.get("detail") else "")
        )

    task_record = _recorded_task(root)
    checks = tuple(str(item) for item in (task_record.get("checks") or ()))
    validate_check_inputs(tuple(task_record.get("check_inputs") or ()))
    goal = str(task_record.get("goal") or "")
    if not goal:
        raise CodeTaskError("the recorded task has no goal to continue")

    worktree = Path(report["worktree"])
    start_commit = report["start_commit"]
    session_id = report["session_id"]
    phases = restore_phase_machine(
        root,
        worktree=worktree,
        start_commit=start_commit,
    )

    if runner is None:
        runner = _default_runner

    verification_events: tuple[dict[str, Any], ...] = ()
    try:
        result = runner(goal, worktree, session_id, phases)
        verification_events = tuple(
            dict(event.get("data") or {})
            for event in getattr(result, "events", ())
            if event.get("type") == "system" and event.get("subtype") == "verification"
        )
        if phases.outcome is None:
            phases.finish(result.subtype)
    except Exception:
        if phases.outcome is None:
            phases.finish("error_during_execution", reason="resumed orchestration raised")
        _write_phases(root, phases)
        raise

    _write_phases(root, phases)
    patch_path = _capture_resumed_patch(root, worktree, start_commit)
    verification_path = _record_resumed_verification(root, verification_events)

    return CodeRunReport(
        run_id=report["run_id"],
        subtype=result.subtype,
        start_commit=start_commit,
        evidence_dir=str(root),
        patch_path=str(patch_path),
        worktree=str(worktree) if keep_worktree else None,
        exit_code=result.exit_code,
        checks=verification_events,
        verification_path=str(verification_path),
        phase_path=str(root / "phases.json"),
        patch_replay_path=(
            str(root / "patch-replay.json") if (root / "patch-replay.json").is_file() else ""
        ),
        patch_audit_path=(
            str(root / "patch-audit.json") if (root / "patch-audit.json").is_file() else ""
        ),
        delivery_seal_path=(
            str(root / "delivery-seal.json") if (root / "delivery-seal.json").is_file() else ""
        ),
    )


def _write_phases(root: Path, phases: CodePhaseMachine) -> None:
    _atomic_write(
        root / "phases.json",
        (
            json.dumps(phases.as_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8"),
    )


def _default_runner(goal: str, worktree: Path, session_id: str, phases: CodePhaseMachine) -> Any:
    """Continue the run with the generic runtime, without the CLI's wrappers."""
    from dataclasses import replace

    from sdk import RunOptions, run as runtime_run

    base = RunOptions()
    allowed = tuple(base.allowed_tools)
    for tool_name in ("Shell", "RunCheck"):
        if tool_name not in allowed:
            allowed = (*allowed, tool_name)
    configured = replace(
        base,
        prompt=goal,
        workspace=str(worktree),
        permission_mode="acceptEdits",
        allowed_tools=allowed,
        session_dir=str(worktree.parent / "sessions"),
        checkpoint_turns=1,
        code_tools=True,
        code_phase_machine=phases,
        resume_from=session_id,
    )
    return runtime_run(configured)


def _capture_resumed_patch(root: Path, worktree: Path, start_commit: str) -> Path:
    from code_task import _current_patch

    patch = _current_patch(worktree)
    path = root / "patch"
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, patch)
    return path


def _record_resumed_verification(
    root: Path, events: tuple[dict[str, Any], ...]
) -> Path:
    path = root / "verification.json"
    payload = {
        "schema": "northstar.code-verification.v1",
        "checks": [dict(event) for event in events],
    }
    _atomic_write(
        path,
        (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return path


__all__ = [
    "RESUMABLE_PHASES",
    "RESUME_RECEIPT_SCHEMA",
    "prepare_code_resume",
    "restore_phase_machine",
    "resume_code_run",
    "write_resume_receipt",
]
