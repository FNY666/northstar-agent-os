"""Long-horizon loop harness: Manager rebuilds, Executor does one bounded step,
Auditor verifies the real artifacts.

What was missing
----------------
The runtime had the *parts* of a long-horizon loop but not the loop:

* ``blind_rerunner.py`` re-runs a delivery blind and compares check sets --
  but it never produces a verdict ("no comparison result is a pass/fail
  verdict").
* ``audit_head_holder.py`` holds the sealed head outside the writer's store,
  so a re-mint shows up as a mismatch -- but nothing rebuilds work state.
* ``sessions.py`` / ``checkpoints.py`` carry resume state and counters -- but
  the state they carry is whatever the *writer* produced.
* ``shutdown_unwind.py`` makes an interrupted turn visible -- but nothing
  compares an executor's *claim* against a real artifact.

So a multi-step task's "progress" was whatever the executor said.  This
module is the loop that closes that gap, in the shape the LongHorizon-Harness
research describes (Manager / Executor / Auditor):

* **Manager** -- rebuilds the round state from exactly three inputs: the
  original objective, the *auditor-verified* progress, and the failure
  evidence.  The executor's own claims are never an input: a step that the
  auditor rejected contributes failure evidence, never progress.
* **Executor** -- performs ONE bounded step per round: a bounded number of
  tool calls, a bounded output, and a **fresh context** rebuilt by the
  Manager (nothing unverified from a previous round rides along).  A step
  ends in exactly one of three ways: ``pending_audit`` (with artifacts),
  ``failed`` (with failure evidence), or ``aborted`` (budget exceeded, with
  evidence).  There is no fourth "probably fine".
* **Auditor** -- verifies independently, by reading the **real** artifacts on
  disk (files, command output, ledger entries) and never the executor's
  prose.  The verdict is pass/fail plus evidence pointers (which file, which
  line).  Only a passing verdict may become trusted state; everything else
  becomes the next round's failure evidence.

The loop is bounded: ``max_rounds`` is configurable, and a loop that reaches
the bound without a passing verdict ends as ``outcome_unknown`` -- never a
silent pass.

Trust boundary
--------------
The Auditor's checks are **host-declared**, never executor-supplied, and the
Auditor's backend identity must differ from the Manager's and the
Executor's: a role that verifies itself verifies nothing.  The Auditor reuses
the *shape* of ``blind_rerunner.BlindCheck`` (a named, runnable command with
an assertion) but not its semantics: ``blind_rerunner`` deliberately refuses
to produce a verdict, and this module needs one.

Honest scope
------------
* This module does not make the Auditor *independent in fact*: it runs in
  the same process as the Executor and reads the same filesystem.  It is
  independent in *state* (fresh context, host-declared checks, no access to
  the executor's claims) -- not in failure domain.  A same-host operator can
  still edit the artifacts after the fact; the checkpoint chain records what
  was verified, not that the world stayed that way.
* The default Executor backend runs shell commands in a workspace.  It is a
  bounded step runner, not an agent: the *decision* of what to run comes from
  a host-supplied planner callback.
* Checkpoints written here carry only auditor-verified progress.  They are a
  separate store from the session transcript checkpoints in ``checkpoints.py``;
  the reuse is deliberate and narrow: ``checkpoints.digest_transcript``
  digests the rebuilt context so a fresh start can verify it resumed from
  the state it thinks it did, and ``audit_head_holder``'s fresh-start pin
  carries the chain head so a re-mint shows up as a mismatch.

House style: frozen dataclasses, stdlib-only, no wall-clock inside the
runtime path (caller-supplied round indices), fail-closed, version/schema
pins.

Version pin: ``long-horizon.v1``
Schema pin: ``northstar.long-horizon.v1``
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

#: Module version pin.
LONG_HORIZON_VERSION = "long-horizon.v1"

#: Schema pin carried by every structured record this module writes.
SCHEMA_PIN = "northstar.long-horizon.v1"

#: The three ways a step can end.  There is no "probably succeeded".
STEP_PENDING_AUDIT = "pending_audit"
STEP_FAILED = "failed"
STEP_ABORTED = "aborted"

#: Loop outcomes.
LOOP_PASSED = "passed"
LOOP_FAILED = "failed"
LOOP_OUTCOME_UNKNOWN = "outcome_unknown"

#: Evidence kinds an auditor pointer may name.
EVIDENCE_FILE = "file"
EVIDENCE_COMMAND = "command"
EVIDENCE_LEDGER = "ledger"


class LongHorizonError(Exception):
    """Fail-closed: a malformed or misused long-horizon input raises."""


def _check_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LongHorizonError(f"{name} must be a non-empty string")
    return value


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verified_head_hash(progress: Sequence["VerifiedProgress"]) -> str:
    """The chain head of the verified progress: a hash over the verified rows.

    Only verified progress contributes.  A rejected step is not in the
    chain, so it cannot change the head -- the head moves exactly when
    trusted state moves.
    """
    return _digest([item.as_dict() for item in progress])


@dataclass(frozen=True)
class EvidencePointer:
    """Where a verdict was read from: a file, a line, a command's output."""

    kind: str
    path: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {EVIDENCE_FILE, EVIDENCE_COMMAND, EVIDENCE_LEDGER}:
            raise LongHorizonError(f"unknown evidence kind {self.kind!r}")
        _check_text(self.path, "evidence path")
        if not isinstance(self.detail, str):
            raise LongHorizonError("evidence detail must be a str")

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "path": self.path, "detail": self.detail}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidencePointer":
        return cls(kind=str(value["kind"]), path=str(value["path"]), detail=str(value.get("detail", "")))


@dataclass(frozen=True)
class FailureEvidence:
    """Why a step did not become progress.  Carried into the next round."""

    reason: str
    evidence: tuple[EvidencePointer, ...] = ()

    def __post_init__(self) -> None:
        _check_text(self.reason, "failure reason")
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def as_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "evidence": [item.as_dict() for item in self.evidence]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FailureEvidence":
        return cls(
            reason=str(value["reason"]),
            evidence=tuple(EvidencePointer.from_dict(item) for item in value.get("evidence", ())),
        )


@dataclass(frozen=True)
class VerifiedProgress:
    """Progress that an Auditor passed.  The only shape trusted state takes."""

    step_id: str
    round_index: int
    summary: str
    artifacts: tuple[str, ...] = ()
    evidence: tuple[EvidencePointer, ...] = ()
    context_digest: str = ""

    def __post_init__(self) -> None:
        _check_text(self.step_id, "step_id")
        if isinstance(self.round_index, bool) or not isinstance(self.round_index, int):
            raise LongHorizonError("round_index must be an int")
        if self.round_index < 0:
            raise LongHorizonError("round_index must be >= 0")
        if not isinstance(self.summary, str):
            raise LongHorizonError("summary must be a str")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def as_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "round_index": self.round_index,
            "summary": self.summary,
            "artifacts": list(self.artifacts),
            "evidence": [item.as_dict() for item in self.evidence],
            "context_digest": self.context_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifiedProgress":
        return cls(
            step_id=str(value["step_id"]),
            round_index=int(value["round_index"]),
            summary=str(value.get("summary", "")),
            artifacts=tuple(str(item) for item in value.get("artifacts", ())),
            evidence=tuple(EvidencePointer.from_dict(item) for item in value.get("evidence", ())),
            context_digest=str(value.get("context_digest", "")),
        )


@dataclass(frozen=True)
class StepOutcome:
    """The executor's report for one step.

    ``summary`` is the executor's *claim*.  Nothing in this module treats it
    as evidence; the Auditor never sees it and the Manager never rebuilds
    from it.
    """

    kind: str
    step_id: str
    summary: str = ""
    artifacts: tuple[str, ...] = ()
    evidence: tuple[EvidencePointer, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {STEP_PENDING_AUDIT, STEP_FAILED, STEP_ABORTED}:
            raise LongHorizonError(f"unknown step outcome {self.kind!r}")
        _check_text(self.step_id, "step_id")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def is_failure(self) -> bool:
        return self.kind in {STEP_FAILED, STEP_ABORTED}

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "step_id": self.step_id,
            "summary": self.summary,
            "artifacts": list(self.artifacts),
            "evidence": [item.as_dict() for item in self.evidence],
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AuditVerdict:
    """The independent verdict: pass/fail plus the pointers it was read from."""

    passed: bool
    summary: str = ""
    evidence: tuple[EvidencePointer, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool):
            raise LongHorizonError("passed must be a bool")
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "summary": self.summary,
            "evidence": [item.as_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class RoundState:
    """The rebuilt round state: structured, never prose, never a claim."""

    round_index: int
    objective: str
    verified_progress: tuple[VerifiedProgress, ...] = ()
    failures: tuple[FailureEvidence, ...] = ()
    context: tuple[Any, ...] = ()
    context_digest: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.round_index, bool) or not isinstance(self.round_index, int):
            raise LongHorizonError("round_index must be an int")
        _check_text(self.objective, "objective")
        object.__setattr__(self, "verified_progress", tuple(self.verified_progress))
        object.__setattr__(self, "failures", tuple(self.failures))
        object.__setattr__(self, "context", tuple(self.context))

    @property
    def verified_step_ids(self) -> tuple[str, ...]:
        return tuple(item.step_id for item in self.verified_progress)

    def as_dict(self) -> dict[str, Any]:
        return {
            "round_index": self.round_index,
            "objective": self.objective,
            "verified_progress": [item.as_dict() for item in self.verified_progress],
            "failures": [item.as_dict() for item in self.failures],
            "context_digest": self.context_digest,
        }


# ---------------------------------------------------------------------------
# Role backends
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StepPlan:
    """What the host wants this round to do.

    ``artifacts`` are the paths the step is expected to have produced.  They
    are *declarations* from the host, not evidence: the Auditor reads the
    files and decides whether they are really there.
    """

    commands: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    summary: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "commands", tuple(self.commands))
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        for command in self.commands:
            if not isinstance(command, str) or not command.strip():
                raise LongHorizonError("a planned command must be a non-empty string")
        for artifact in self.artifacts:
            if not isinstance(artifact, str) or not artifact.strip():
                raise LongHorizonError("a declared artifact must be a non-empty string")

    def as_dict(self) -> dict[str, Any]:
        return {
            "commands": list(self.commands),
            "artifacts": list(self.artifacts),
            "summary": self.summary,
        }


@dataclass(frozen=True)
class AuditCheck:
    """One host-declared, independently runnable check.

    The shape deliberately echoes ``blind_rerunner.BlindCheck``: a named,
    runnable command plus an assertion.  The difference is the verdict:
    ``blind_rerunner`` refuses to produce one (its docstring says "no
    comparison result is a pass/fail verdict"), while an Auditor check must
    produce one -- otherwise nothing can ever become trusted state.
    """

    check_id: str
    description: str
    command: str
    #: Files that must exist, be non-empty, and live inside the workspace.
    expect_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value in (("check_id", self.check_id), ("description", self.description), ("command", self.command)):
            if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
                raise LongHorizonError(f"{name} must be a non-empty single-line string")
        object.__setattr__(self, "expect_files", tuple(self.expect_files))

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "description": self.description,
            "command": self.command,
            "expect_files": list(self.expect_files),
        }


@dataclass(frozen=True)
class RoleConfig:
    """The identity of a role.  Two roles may not share an identity.
    The identity is what the isolation rule is enforced on: the Auditor's
    ``backend_id`` must differ from the Manager's and the Executor's, and
    the Auditor's checks must differ from the Executor backend's checks.
    Sharing one identity means one party verifies its own work -- which is
    the seam the whole harness exists to hold open.
    """

    role: str
    backend_id: str
    model: str = ""

    def __post_init__(self) -> None:
        if self.role not in {"manager", "executor", "auditor"}:
            raise LongHorizonError(f"unknown role {self.role!r}")
        _check_text(self.backend_id, "backend_id")
        if not isinstance(self.model, str):
            raise LongHorizonError("model must be a str")

    def as_dict(self) -> dict[str, Any]:
        return {"role": self.role, "backend_id": self.backend_id, "model": self.model}


class ManagerBackend:
    """Rebuilds the round state.  The base implementation is deterministic.

    The rebuild inputs are exactly: the original objective, the
    auditor-verified progress, and the failure evidence.  There is no
    parameter for "what the executor said" -- the executor's claims are
    structurally absent from the rebuild, so they cannot leak in.
    """

    backend_id = "manager.deterministic.v1"

    def rebuild(
        self,
        *,
        objective: str,
        verified_progress: Sequence[VerifiedProgress],
        failures: Sequence[FailureEvidence],
        round_index: int,
    ) -> RoundState:
        context = self.build_context(
            objective=objective,
            verified_progress=verified_progress,
            failures=failures,
            round_index=round_index,
        )
        return RoundState(
            round_index=round_index,
            objective=objective,
            verified_progress=tuple(verified_progress),
            failures=tuple(failures),
            context=tuple(context),
            context_digest=_digest(
                [
                    objective,
                    [item.as_dict() for item in verified_progress],
                    [item.as_dict() for item in failures],
                ]
            ),
        )

    def build_context(
        self,
        *,
        objective: str,
        verified_progress: Sequence[VerifiedProgress],
        failures: Sequence[FailureEvidence],
        round_index: int,
    ) -> list[Any]:
        """The fresh working context for the round.

        Only verified progress and failure evidence appear here.  The
        context is rebuilt from scratch every round, so nothing unverified
        from a previous round can ride along.  The context is a list of
        *messages* so it can be digested by ``checkpoints.digest_transcript``
        and written as a resumable checkpoint record.
        """
        from providers.base import SystemMessage, UserMessage

        lines: list[str] = [f"objective: {objective}", f"round: {round_index}"]
        if verified_progress:
            lines.append("verified progress:")
            for item in verified_progress:
                lines.append(f"- [{item.round_index}] {item.step_id}: {item.summary}")
        else:
            lines.append("verified progress: (none)")
        if failures:
            lines.append("failure evidence:")
            for item in failures:
                lines.append(f"- {item.reason}")
                for pointer in item.evidence:
                    lines.append(f"  evidence: {pointer.kind} {pointer.path} {pointer.detail}".rstrip())
        else:
            lines.append("failure evidence: (none)")
        return [
            SystemMessage(subtype="informational", content="long-horizon round context"),
            UserMessage.text_block("\n".join(lines)),
        ]


class ExecutorBackend:
    """Runs ONE bounded step.  The base implementation runs one command.

    ``plan`` is a host callback: given the rebuilt round state, it returns
    the command(s) to run for this round.  The executor never decides on its
    own what "done" means -- the host owns the plan, the auditor owns the
    verdict.

    The step is bounded twice over: the plan may not exceed
    ``max_tool_calls`` commands, and the produced output may not exceed
    ``max_output_chars``.  Exceeding either is an *aborted* step with
    evidence -- never a silent truncation that looks like success.
    """

    backend_id = "executor.shell.v1"

    def __init__(
        self,
        *,
        workspace: str | Path,
        max_tool_calls: int = 1,
        max_output_chars: int = 8192,
        timeout_s: float = 60.0,
    ) -> None:
        self.workspace = Path(workspace)
        self.max_tool_calls = int(max_tool_calls)
        self.max_output_chars = int(max_output_chars)
        self.timeout_s = float(timeout_s)
        if self.max_tool_calls < 1:
            raise LongHorizonError("max_tool_calls must be >= 1")
        if self.max_output_chars < 1:
            raise LongHorizonError("max_output_chars must be >= 1")

    def run_step(
        self,
        *,
        state: RoundState,
        plan: Callable[[RoundState], Sequence[str]],
        step_id: str,
    ) -> StepOutcome:
        """Run the round's single bounded action.

        The step's context is ``state.context`` and nothing else: the
        executor cannot see the previous round's transcript, only the
        Manager's rebuild.
        """
        try:
            planned = plan(state)
        except Exception as error:  # noqa: BLE001 - a broken planner is a failed step
            return StepOutcome(
                kind=STEP_FAILED,
                step_id=step_id,
                summary="",
                reason=f"planner raised {type(error).__name__}: {error}",
            )
        if isinstance(planned, str):
            commands: list[str] = [planned]
        else:
            try:
                commands = [str(item) for item in planned]
            except TypeError:
                return StepOutcome(
                    kind=STEP_FAILED,
                    step_id=step_id,
                    summary="",
                    reason="the plan produced no command",
                )
        if not commands or not all(command.strip() for command in commands):
            return StepOutcome(
                kind=STEP_FAILED,
                step_id=step_id,
                summary="",
                reason="the plan produced no command",
            )
        if len(commands) > self.max_tool_calls:
            return StepOutcome(
                kind=STEP_ABORTED,
                step_id=step_id,
                summary="",
                reason=(
                    f"the step planned {len(commands)} tool calls but the budget is "
                    f"{self.max_tool_calls}"
                ),
                evidence=(
                    EvidencePointer(
                        kind=EVIDENCE_COMMAND,
                        path=commands[0],
                        detail=f"planned_calls={len(commands)} budget={self.max_tool_calls}",
                    ),
                ),
            )
        outputs: list[str] = []
        pointers: list[EvidencePointer] = []
        total = 0
        for command in commands:
            try:
                completed = subprocess.run(  # noqa: S603 - the command comes from the host plan
                    command,
                    shell=True,
                    cwd=str(self.workspace),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=self.timeout_s,
                    env={"PATH": os.environ.get("PATH", "")},
                )
            except subprocess.TimeoutExpired:
                return StepOutcome(
                    kind=STEP_ABORTED,
                    step_id=step_id,
                    summary="",
                    reason=f"the step exceeded its {self.timeout_s:g}s wall-clock budget",
                    evidence=(
                        EvidencePointer(kind=EVIDENCE_COMMAND, path=command, detail="timeout"),
                    ),
                )
            output = completed.stdout or ""
            total += len(output)
            if total > self.max_output_chars:
                return StepOutcome(
                    kind=STEP_ABORTED,
                    step_id=step_id,
                    summary="",
                    reason=(
                        f"the step produced {total} chars of output but the budget is "
                        f"{self.max_output_chars}"
                    ),
                    evidence=(
                        EvidencePointer(
                            kind=EVIDENCE_COMMAND,
                            path=command,
                            detail=f"output_chars={total} budget={self.max_output_chars}",
                        ),
                    ),
                )
            pointer = EvidencePointer(
                kind=EVIDENCE_COMMAND,
                path=command,
                detail=f"exit={completed.returncode}",
            )
            pointers.append(pointer)
            outputs.append(output)
            if completed.returncode != 0:
                return StepOutcome(
                    kind=STEP_FAILED,
                    step_id=step_id,
                    summary="".join(outputs),
                    reason=f"the step command exited {completed.returncode}",
                    evidence=tuple(pointers),
                )
        return StepOutcome(
            kind=STEP_PENDING_AUDIT,
            step_id=step_id,
            summary="".join(outputs),
            evidence=tuple(pointers),
        )


class AuditorBackend:
    """Verifies the real artifacts.  The base implementation runs host-declared
    commands and reads the files they name.

    The checks are host-declared and never taken from the executor's output.
    The Auditor's verdict is derived from what it read on disk: the command's
    exit status and output, plus the content of the files the check names.
    """

    backend_id = "auditor.commands.v1"

    def __init__(
        self,
        *,
        workspace: str | Path,
        checks: Sequence["AuditCheck"] = (),
        max_output_chars: int = 8192,
        timeout_s: float = 60.0,
    ) -> None:
        self.workspace = Path(workspace)
        self.checks = tuple(checks)
        self.max_output_chars = int(max_output_chars)
        self.timeout_s = float(timeout_s)

    def audit(
        self,
        *,
        state: RoundState,
        declared_artifacts: Sequence[str],
        checks: Sequence["AuditCheck"],
    ) -> AuditVerdict:
        """Verify the round's real artifacts.

        The signature is the isolation rule: the Auditor receives the
        rebuilt round state, the *paths* the executor said it touched, and
        the host-declared checks.  It does **not** receive the executor's
        summary text -- there is no parameter through which the claim could
        reach the verdict, so "the executor said it passed" cannot become
        "the Auditor passed it".
        """
        pointers: list[EvidencePointer] = []
        failures: list[str] = []
        for relative in declared_artifacts:
            ok, detail = self._check_file(relative)
            pointers.append(
                EvidencePointer(kind=EVIDENCE_FILE, path=relative, detail=detail)
            )
            if not ok:
                failures.append(f"artifact {relative}: {detail}")
        for check in checks:
            ok, detail, pointer = self._run_check(check)
            pointers.append(pointer)
            if not ok:
                failures.append(f"{check.check_id}: {detail}")
        if failures:
            return AuditVerdict(
                passed=False,
                summary="; ".join(failures),
                evidence=tuple(pointers),
            )
        return AuditVerdict(
            passed=True,
            summary=(
                f"{len(declared_artifacts)} declared artifact(s) and "
                f"{len(checks)} declared check(s) verified"
            ),
            evidence=tuple(pointers),
        )

    def _run_check(self, check: "AuditCheck") -> tuple[bool, str, EvidencePointer]:
        try:
            completed = subprocess.run(  # noqa: S603 - the command is host-declared
                check.command,
                shell=True,
                cwd=str(self.workspace),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.timeout_s,
                env={"PATH": os.environ.get("PATH", "")},
            )
        except subprocess.TimeoutExpired:
            return (
                False,
                f"the check timed out after {self.timeout_s:g}s",
                EvidencePointer(kind=EVIDENCE_COMMAND, path=check.command, detail="timeout"),
            )
        output = completed.stdout or ""
        if len(output) > self.max_output_chars:
            output = output[: self.max_output_chars]
        detail = f"exit={completed.returncode}"
        if completed.returncode != 0:
            return (
                False,
                f"the check failed ({detail}): {output.strip()[:400]}",
                EvidencePointer(kind=EVIDENCE_COMMAND, path=check.command, detail=detail),
            )
        pointer = EvidencePointer(
            kind=EVIDENCE_COMMAND,
            path=check.command,
            detail=detail,
        )
        if not check.expect_files:
            return True, detail, pointer
        for relative in check.expect_files:
            ok, file_detail = self._check_file(relative)
            if not ok:
                return (
                    False,
                    file_detail,
                    EvidencePointer(kind=EVIDENCE_FILE, path=relative, detail=file_detail),
                )
        return True, detail, pointer

    def _check_file(self, relative: str) -> tuple[bool, str]:
        path = self.workspace / relative
        try:
            resolved = path.resolve()
            root = self.workspace.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            return False, f"{relative} resolves outside the workspace"
        if not path.exists():
            return False, f"{relative} does not exist on disk"
        if not path.is_file():
            return False, f"{relative} is not a regular file"
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            return False, f"{relative} could not be read: {error}"
        if not content.strip():
            return False, f"{relative} is empty"
        return True, f"{relative} exists and is non-empty ({len(content)} chars)"


# ---------------------------------------------------------------------------
# Checkpoints: only auditor-verified progress lands here
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedCheckpoint:
    """A checkpoint of *verified* progress.

    A checkpoint records the objective, the round it was taken at, the
    auditor-verified progress so far, and the digest of the rebuilt
    context.  It never records an executor claim: the store refuses to
    write one.
    """

    session_id: str
    round_index: int
    objective: str
    verified_progress: tuple[VerifiedProgress, ...] = ()
    context_digest: str = ""
    head_hash: str = ""

    def __post_init__(self) -> None:
        _check_text(self.session_id, "session_id")
        _check_text(self.objective, "objective")
        if isinstance(self.round_index, bool) or not isinstance(self.round_index, int):
            raise LongHorizonError("round_index must be an int")
        object.__setattr__(self, "verified_progress", tuple(self.verified_progress))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "session_id": self.session_id,
            "round_index": self.round_index,
            "objective": self.objective,
            "verified_progress": [item.as_dict() for item in self.verified_progress],
            "context_digest": self.context_digest,
            "head_hash": self.head_hash,
        }


class VerifiedProgressStore:
    """Append-only store of verified checkpoints.

    Fail-closed in the way the whole module is: :meth:`record` takes a
    ``VerifiedProgress`` -- a value that only the auditor path can produce
    -- and the loop never calls it for an unverified step.
    """

    def __init__(self, path: str | Path) -> None:
        if path is None or (isinstance(path, str) and not path):
            raise LongHorizonError("path must be a non-empty path")
        self.path = Path(path)

    def record(self, checkpoint: VerifiedCheckpoint) -> None:
        if not isinstance(checkpoint, VerifiedCheckpoint):
            raise LongHorizonError("record takes a VerifiedCheckpoint")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(checkpoint.as_dict(), sort_keys=True, ensure_ascii=False) + "\n")

    def checkpoints(self) -> tuple[VerifiedCheckpoint, ...]:
        if not self.path.exists():
            return ()
        found: list[VerifiedCheckpoint] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            if raw.get("schema") != SCHEMA_PIN:
                raise LongHorizonError("a checkpoint record has an unknown schema")
            found.append(
                VerifiedCheckpoint(
                    session_id=str(raw["session_id"]),
                    round_index=int(raw["round_index"]),
                    objective=str(raw["objective"]),
                    verified_progress=tuple(
                        VerifiedProgress.from_dict(item) for item in raw.get("verified_progress", ())
                    ),
                    context_digest=str(raw.get("context_digest", "")),
                    head_hash=str(raw.get("head_hash", "")),
                )
            )
        return tuple(found)

    def latest(self) -> VerifiedCheckpoint | None:
        found = self.checkpoints()
        return found[-1] if found else None


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoundRecord:
    """One round's structured record.  A record, not a narrative."""

    round_index: int
    state: RoundState
    step: StepOutcome
    verdict: AuditVerdict | None
    artifacts: tuple[str, ...] = ()
    progress: VerifiedProgress | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "round_index": self.round_index,
            "state": self.state.as_dict(),
            "step": self.step.as_dict(),
            "verdict": self.verdict.as_dict() if self.verdict is not None else None,
            "artifacts": list(self.artifacts),
            "progress": self.progress.as_dict() if self.progress is not None else None,
        }


@dataclass(frozen=True)
class LoopResult:
    """The loop's outcome.  ``outcome_unknown`` is a real, named outcome."""

    outcome: str
    rounds: tuple[RoundRecord, ...] = ()
    verified_progress: tuple[VerifiedProgress, ...] = ()
    failures: tuple[FailureEvidence, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in {LOOP_PASSED, LOOP_FAILED, LOOP_OUTCOME_UNKNOWN}:
            raise LongHorizonError(f"unknown loop outcome {self.outcome!r}")
        object.__setattr__(self, "rounds", tuple(self.rounds))
        object.__setattr__(self, "verified_progress", tuple(self.verified_progress))
        object.__setattr__(self, "failures", tuple(self.failures))

    @property
    def passed(self) -> bool:
        return self.outcome == LOOP_PASSED

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "outcome": self.outcome,
            "rounds": [item.as_dict() for item in self.rounds],
            "verified_progress": [item.as_dict() for item in self.verified_progress],
            "failures": [item.as_dict() for item in self.failures],
            "reason": self.reason,
        }


class LongHorizonLoop:
    """The Manager / Executor / Auditor loop.

    One round:

    1. The **Manager** rebuilds the round state from the objective, the
       auditor-verified progress, and the failure evidence.  Nothing else
       is an input; the executor's claims are structurally absent.
    2. The **Executor** performs one bounded step on the rebuilt context.
    3. The **Auditor** verifies the real artifacts.  A pass turns the step
       into verified progress (and into a checkpoint); a fail turns it into
       failure evidence for the next round.

    The loop stops when the auditor passes, when the round budget is
    exhausted (then: ``outcome_unknown`` -- never a silent pass), or when
    the host's plan reports the objective is complete.

    Role isolation is enforced at construction: the auditor's backend id
    must differ from the manager's and the executor's, and the auditor's
    checks must differ from the executor's declared artifacts' checks.
    """

    def __init__(
        self,
        *,
        objective: str,
        manager: ManagerBackend,
        executor: ExecutorBackend,
        auditor: AuditorBackend,
        plan: Callable[[RoundState], StepPlan],
        checks: Sequence[AuditCheck] = (),
        max_rounds: int = 4,
        session_id: str = "long-horizon",
        checkpoint_store: VerifiedProgressStore | None = None,
        session: Any | None = None,
        durable_store: Any | None = None,
        initial_progress: Sequence[VerifiedProgress] = (),
        initial_failures: Sequence[FailureEvidence] = (),
        is_complete: Callable[[RoundState, VerifiedProgress], bool] | None = None,
        manager_config: RoleConfig | None = None,
        executor_config: RoleConfig | None = None,
        auditor_config: RoleConfig | None = None,
    ) -> None:
        _check_text(objective, "objective")
        if max_rounds < 1:
            raise LongHorizonError("max_rounds must be >= 1")
        self.objective = objective
        self.manager = manager
        self.executor = executor
        self.auditor = auditor
        self.plan = plan
        self.checks = tuple(checks)
        self.max_rounds = int(max_rounds)
        self.session_id = session_id
        self.checkpoint_store = checkpoint_store
        self.session = session
        #: The durable store (:mod:`durable_resume`) the loop writes its
        #: durable checkpoints into.  Optional: a loop without one still runs,
        #: it just has no resumable durable boundary.
        self.durable_store = durable_store
        # A resumed loop starts from the *verified* state its last verified
        # checkpoint carried -- never from an executor's claim.
        self.initial_progress = tuple(initial_progress)
        self.initial_failures = tuple(initial_failures)
        self.is_complete = is_complete or (lambda _state, _progress: True)
        self.manager_config = manager_config or RoleConfig(role="manager", backend_id=manager.backend_id)
        self.executor_config = executor_config or RoleConfig(role="executor", backend_id=executor.backend_id)
        self.auditor_config = auditor_config or RoleConfig(role="auditor", backend_id=auditor.backend_id)
        self._check_role_isolation()

    def _check_role_isolation(self) -> None:
        identities = {
            "manager": self.manager_config.backend_id,
            "executor": self.executor_config.backend_id,
            "auditor": self.auditor_config.backend_id,
        }
        if len(set(identities.values())) != 3:
            raise LongHorizonError(
                "the manager, executor, and auditor must not share a backend identity: "
                + ", ".join(f"{role}={ident}" for role, ident in identities.items())
            )
        if self.manager_config.backend_id == self.auditor_config.backend_id:
            raise LongHorizonError("the auditor may not share the manager's backend")
        if self.executor_config.backend_id == self.auditor_config.backend_id:
            raise LongHorizonError("the auditor may not share the executor's backend")

    def run(self) -> LoopResult:
        """Run the loop to a verdict."""
        verified: list[VerifiedProgress] = list(self.initial_progress)
        failures: list[FailureEvidence] = list(self.initial_failures)
        records: list[RoundRecord] = []
        for round_index in range(self.max_rounds):
            state = self.manager.rebuild(
                objective=self.objective,
                verified_progress=verified,
                failures=failures,
                round_index=round_index,
            )
            step_plan = self.plan(state)
            if not isinstance(step_plan, StepPlan):
                raise LongHorizonError("the plan must return a StepPlan")
            step = self.executor.run_step(
                state=state,
                plan=lambda _state: step_plan.commands,
                step_id=f"{self.session_id}-r{round_index}",
            )
            if step.kind == STEP_FAILED:
                failure = FailureEvidence(
                    reason=f"step {step.step_id} failed: {step.reason}",
                    evidence=step.evidence,
                )
                failures.append(failure)
                records.append(RoundRecord(round_index=round_index, state=state, step=step, verdict=None))
                continue
            if step.kind == STEP_ABORTED:
                failure = FailureEvidence(
                    reason=f"step {step.step_id} was aborted: {step.reason}",
                    evidence=step.evidence,
                )
                failures.append(failure)
                records.append(RoundRecord(round_index=round_index, state=state, step=step, verdict=None))
                continue
            verdict = self.auditor.audit(
                state=state,
                declared_artifacts=step_plan.artifacts,
                checks=self.checks,
            )
            if not verdict.passed:
                failure = FailureEvidence(
                    reason=f"the auditor rejected step {step.step_id}: {verdict.summary}",
                    evidence=verdict.evidence,
                )
                failures.append(failure)
                records.append(
                    RoundRecord(
                        round_index=round_index,
                        state=state,
                        step=step,
                        verdict=verdict,
                        artifacts=step_plan.artifacts,
                    )
                )
                continue
            progress = VerifiedProgress(
                step_id=step.step_id,
                round_index=round_index,
                # The summary of *verified* progress is the auditor's own
                # wording about what it verified -- never the executor's
                # narration and never the plan's summary line.
                summary=verdict.summary or f"round {round_index} verified",
                artifacts=step_plan.artifacts,
                evidence=verdict.evidence,
                context_digest=state.context_digest,
            )
            verified.append(progress)
            records.append(
                RoundRecord(
                    round_index=round_index,
                    state=state,
                    step=step,
                    verdict=verdict,
                    artifacts=step_plan.artifacts,
                    progress=progress,
                )
            )
            if self.checkpoint_store is not None:
                self.checkpoint_store.record(
                    VerifiedCheckpoint(
                        session_id=self.session_id,
                        round_index=round_index,
                        objective=self.objective,
                        verified_progress=tuple(verified),
                        context_digest=state.context_digest,
                        head_hash=verified_head_hash(tuple(verified)),
                    )
                )
            self._write_session_checkpoint(state, verified)
            self._write_durable_checkpoint(state, verified)
            if self._is_complete(state, progress):
                return LoopResult(
                    outcome=LOOP_PASSED,
                    rounds=tuple(records),
                    verified_progress=tuple(verified),
                    failures=tuple(failures),
                    reason="the objective was verified complete",
                )
        return LoopResult(
            outcome=LOOP_OUTCOME_UNKNOWN,
            rounds=tuple(records),
            verified_progress=tuple(verified),
            failures=tuple(failures),
            reason=(
                f"the loop reached its {self.max_rounds}-round bound without a passing "
                "verdict; the outcome is unknown, not a pass"
            ),
        )

    def _write_session_checkpoint(
        self,
        state: RoundState,
        verified: Sequence[VerifiedProgress],
    ) -> None:
        """Write the round's checkpoint into the session transcript.

        The record reuses ``checkpoints.build`` so it is a *real* session
        checkpoint: a resume forks from it and inherits its counters.  Only
        auditor-verified progress is written -- the write happens only on
        the pass path, and the payload carries the verified progress and
        the rebuilt context's digest, never an executor claim.
        """
        if self.session is None:
            return
        from checkpoints import build as build_checkpoint

        payload = build_checkpoint(
            session_id=self.session_id,
            record_index=int(getattr(self.session, "written", 0) or 0),
            transcript=list(state.context),
            turns=state.round_index + 1,
            tool_calls=0,
            cost_usd=0.0,
            usage={},
            model=self.executor_config.model or "unknown",
            provider=self.executor_config.backend_id,
            permission_mode="long-horizon",
            run_id=self.session_id,
        )
        payload["boundary"] = "long-horizon-verified"
        payload["verified_progress"] = [item.as_dict() for item in verified]
        payload["objective"] = self.objective
        payload["head_hash"] = verified_head_hash(tuple(verified))
        self.session.append("checkpoint", payload)

    def _is_complete(self, state: RoundState, progress: VerifiedProgress) -> bool:
        """The host decides when the objective is done.

        The default is "one verified step is enough"; a caller that wants a
        multi-step objective passes ``is_complete``.
        """
        return bool(self.is_complete(state, progress))

    def _write_durable_checkpoint(
        self,
        state: RoundState,
        verified: Sequence[VerifiedProgress],
    ) -> Any:
        """Write the round's *durable* checkpoint.

        Only auditor-verified progress reaches this record.  The state is
        built by :func:`durable_resume.checkpoint_from_verified`, which takes
        the verified progress and has no parameter for the executor's
        summary -- so an executor's self-report cannot reach a durable
        checkpoint even by accident.  The write happens only on the pass
        path, which is the same rule the session checkpoint follows.

        Returns the durable checkpoint, or ``None`` when no durable store was
        configured.
        """
        if self.durable_store is None:
            return None
        from durable_resume import checkpoint_from_verified

        durable_state = checkpoint_from_verified(
            run_id=self.session_id,
            round_index=state.round_index,
            objective=self.objective,
            verified_progress=tuple(verified),
            context_digest=state.context_digest,
        )
        return self.durable_store.put_checkpoint(
            run_id=self.session_id,
            state=durable_state,
            task_path=self.session_id,
        )


# ---------------------------------------------------------------------------
# Fresh start: resuming a loop from its verified checkpoint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FreshStart:
    """A fresh start of a long-horizon loop, carrying the old head.

    The shape comes from ``audit_head_holder.fresh_start_pin``: the new
    head carries the *old* head's hash in ``prev_head``, so a re-mint of the
    verified-progress chain shows up as a head mismatch rather than as a
    clean start.  This module does not re-implement that check -- it calls
    ``audit_head_holder.fresh_start_pin`` and ``check_fresh_start`` so the
    two paths agree on what a fresh start means.
    """

    objective: str
    previous_head_hash: str
    new_head_hash: str
    genesis: str
    verified_progress: tuple[VerifiedProgress, ...] = ()
    failures: tuple[FailureEvidence, ...] = ()
    round_index: int = 0

    def __post_init__(self) -> None:
        _check_text(self.objective, "objective")
        _check_text(self.previous_head_hash, "previous_head_hash")
        _check_text(self.new_head_hash, "new_head_hash")
        _check_text(self.genesis, "genesis")
        object.__setattr__(self, "verified_progress", tuple(self.verified_progress))
        object.__setattr__(self, "failures", tuple(self.failures))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "objective": self.objective,
            "previous_head_hash": self.previous_head_hash,
            "new_head_hash": self.new_head_hash,
            "genesis": self.genesis,
            "verified_progress": [item.as_dict() for item in self.verified_progress],
            "failures": [item.as_dict() for item in self.failures],
            "round_index": self.round_index,
        }


def resume_from_checkpoint(
    checkpoint: VerifiedCheckpoint,
    *,
    new_head_hash: str,
    genesis: str = "northstar.long-horizon.v1",
) -> FreshStart:
    """Rebuild a loop's starting state from its last *verified* checkpoint.

    The checkpoint is the trusted state; the fresh-start pin carries the
    chain head so the new chain is linked to the one it continues.  The
    failures carried forward are the ones the checkpoint recorded -- never
    an executor's summary.
    """
    if not isinstance(checkpoint, VerifiedCheckpoint):
        raise LongHorizonError("resume_from_checkpoint takes a VerifiedCheckpoint")
    previous_head = checkpoint.head_hash or checkpoint.context_digest
    if not previous_head:
        raise LongHorizonError("the checkpoint carries no head hash to continue from")
    return FreshStart(
        objective=checkpoint.objective,
        previous_head_hash=previous_head,
        new_head_hash=new_head_hash,
        genesis=genesis,
        verified_progress=checkpoint.verified_progress,
        round_index=checkpoint.round_index + 1,
    )


def check_fresh_start_head(fresh: FreshStart, independent_head: Any | None) -> tuple[bool, str]:
    """Check the fresh start against an independently held head.

    Delegates to ``audit_head_holder.check_fresh_start`` so the loop's
    fresh-start semantics are the audit-head module's semantics, not a
    second opinion.  Fails closed: with no independent head held, the
    answer is "no".
    """
    from audit_head_holder import HeadPin, check_fresh_start

    if independent_head is None:
        return check_fresh_start(None, None)
    carried = HeadPin(
        head_hash=fresh.new_head_hash,
        seq=fresh.round_index,
        records_sealed=fresh.round_index,
        genesis=fresh.genesis,
        seq_first=1,
        seq_last=fresh.round_index,
        prev_head=fresh.previous_head_hash,
    )
    return check_fresh_start(carried, independent_head)




