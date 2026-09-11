"""One goal in, one independently verified deliverable out.

The governed loop knows nothing about tools, authorization, or the filesystem:
host code binds those. This module is that host binding for a multi-step local
task, and it is the first entry point in this repository that runs a whole
task end to end:

    goal → planner candidate → admission → per-step authorization
         → bounded real tools (read + sandboxed write) → independent
         observation → bounded autonomous resume → independent final check

Boundaries (what this is not): it runs in-process, it has no network tool, no
command execution, no re-planning loop, no approval UI, and no distributed
scheduling. It is a local harness, not a hosted agent service.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from action_gateway import ActionGateway, ToolSpec
from agent_loop import AgentLoop, PostconditionResult
from authorization import HostPolicy, authorize_run
from binding import sign_binding, verify_binding
from durable_contract import RunContract
from governed_dispatch import GovernedActionDispatcher
from repo_read import RepoReadTool
from workspace_list import WorkspaceListTool
from workspace_write import WorkspaceWriteTool

LIST_ACTION = "workspace.list"
READ_ACTION = "repo.read"
WRITE_ACTION = "workspace.write"
READ_CAPABILITY = "workspace:read"
WRITE_CAPABILITY = "workspace:write"
RUN_SCHEMA = "northstar.run.v1"
_MAX_PATH = 1024


def _relative_parts(path: object) -> list[str]:
    if not isinstance(path, str) or not path or len(path) > _MAX_PATH:
        raise ValueError("invalid relative path")
    parts = path.split("/")
    if any(p in {"", ".", ".."} or "\\" in p or "\x00" in p for p in parts):
        raise ValueError("invalid relative path")
    return parts


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_run(
    task_id: str,
    *,
    clock: Callable[[], int] | None = None,
    deadline_seconds: int = 600,
    thread_id: str | None = None,
    scope: tuple[str, ...] = (READ_CAPABILITY, WRITE_CAPABILITY),
) -> RunContract:
    """Host-owned run identity; the model never supplies these fields."""
    now = (clock or (lambda: int(time.time())))()
    return RunContract.from_dict(
        {
            "schema_version": "northstar.durable-run.v1",
            "task_id": task_id,
            "thread_id": thread_id or f"thread-{task_id}",
            "run_id": f"run-{task_id}",
            "parent_run_id": None,
            "status": "planned",
            "deadline_at": now + deadline_seconds,
            "scope_snapshot": list(scope),
            "trace_id": f"trace-{task_id}",
        }
    )


@dataclass(frozen=True)
class ExpectedArtifact:
    """Host-owned definition of a deliverable; the plan cannot redefine it."""

    path: str
    content: str | None = None
    digest: str | None = None
    absent: bool = False
    contains: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        _relative_parts(self.path)
        declared = [
            self.content is not None,
            self.digest is not None,
            self.absent,
            self.contains is not None,
        ]
        if sum(declared) != 1:
            raise ValueError("expected artifact needs exactly one expectation")
        if self.digest is not None and not self.digest.startswith("sha256:"):
            raise ValueError("expected digest must be a sha256 digest")
        if self.contains is not None and (
            not isinstance(self.contains, tuple)
            or not self.contains
            or any(not isinstance(item, str) or not item for item in self.contains)
        ):
            raise ValueError("expected contains must be a non-empty tuple of strings")


@dataclass(frozen=True)
class DeliverableVerification:
    verdict: str
    checked: tuple[str, ...]
    failures: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "checked": list(self.checked),
            "failures": list(self.failures),
        }


@dataclass(frozen=True)
class StepOutcome:
    step_id: str
    action_id: str
    status: str
    reason_code: str | None
    attempts: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action_id": self.action_id,
            "status": self.status,
            "reason_code": self.reason_code,
            "attempts": self.attempts,
        }


@dataclass(frozen=True)
class TaskOutcome:
    task_id: str
    goal: str
    run_status: str
    verification: DeliverableVerification
    steps: tuple[StepOutcome, ...]
    planner_attempts: int
    resumes: int
    evidence_events: int

    @property
    def ok(self) -> bool:
        """A task is done only when the loop finished and a host check verified it."""
        return self.run_status == "finished" and self.verification.verdict == "verified"

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "goal": self.goal,
            "run_status": self.run_status,
            "ok": self.ok,
            "planner_attempts": self.planner_attempts,
            "resumes": self.resumes,
            "evidence_events": self.evidence_events,
            "verification": self.verification.as_dict(),
            "steps": [step.as_dict() for step in self.steps],
        }


class AgentHarness:
    """Bind one run, one workspace root, two real tools, and one observer."""

    def __init__(
        self,
        run: RunContract,
        workspace_root: str | Path,
        evidence_path: str | Path,
        *,
        actor_id: str,
        workspace_id: str,
        policy_revision: str = "policy-agent-1",
        task_kind: str = "implementation",
        secrets: dict[str, bytes] | None = None,
        allowed_read_paths=None,
        allowed_write_paths=None,
        max_read_bytes: int = 4096,
        max_write_bytes: int = 65_536,
        clock: Callable[[], int] | None = None,
        grant_ttl_seconds: int = 900,
        timeout_ms: int = 300_000,
        max_resumes: int = 2,
        faults: dict[str, Callable[..., None]] | None = None,
        observer_hook: Callable[..., Any] | None = None,
    ):
        if not isinstance(run, RunContract):
            raise ValueError("run must be a RunContract")
        self.run = run
        self.actor_id = actor_id
        self.workspace_id = workspace_id
        self.policy_revision = policy_revision
        self.workspace_root = Path(os.path.realpath(workspace_root))
        if not self.workspace_root.is_dir():
            raise ValueError("workspace root must be an existing directory")
        self.evidence_path = Path(evidence_path)
        if type(max_resumes) is not int or not 0 <= max_resumes <= 8:
            raise ValueError("max_resumes is invalid")
        self.max_resumes = max_resumes
        self._now = clock or (lambda: int(time.time()))

        supplied = dict(secrets or {})
        self._binding_secret = supplied.get("binding") or os.urandom(32)
        self._authorization_secret = supplied.get("authorization") or os.urandom(32)
        self._approval_secret = supplied.get("approval") or os.urandom(32)

        self._read_tool = RepoReadTool(self.workspace_root, allowed_paths=allowed_read_paths)
        self._list_tool = WorkspaceListTool(self.workspace_root)
        self._write_tool = WorkspaceWriteTool(
            self.workspace_root,
            allowed_paths=allowed_write_paths,
            max_bytes=max_write_bytes,
        )
        self._max_read_bytes = max_read_bytes
        self._faults = dict(faults or {})
        if observer_hook is not None and not callable(observer_hook):
            raise ValueError("observer_hook must be callable")
        self._observer_hook = observer_hook
        self._observations: dict[str, int] = {}
        self._attempts: dict[str, int] = {}
        self._registered: set[str] = set()
        self._admitted_steps: list[Any] = []

        self._run_request = {
            "schema_version": RUN_SCHEMA,
            "run_id": run.run_id,
            "actor_id": actor_id,
            "workspace_id": workspace_id,
            "task_kind": task_kind,
            "prompt": f"host-bound run for task {run.task_id}",
            "timeout_ms": timeout_ms,
            "requested_capabilities": list(run.scope_snapshot),
            "parent_run_id": None,
        }
        self._binding = verify_binding(self._binding_token(grant_ttl_seconds), self._binding_secret, now=self.now())
        self._policy = HostPolicy.from_mapping(
            policy_revision, {actor_id: list(run.scope_snapshot)}
        )
        self._grant_ttl_seconds = grant_ttl_seconds

        self.gateway = ActionGateway(approval_secret=self._approval_secret)
        self.gateway.register(
            ToolSpec(
                name=READ_ACTION,
                required_capability=READ_CAPABILITY,
                required_scope=READ_CAPABILITY,
                resource_kind="workspace",
                risk_level="low",
                executor=self._read_executor,
            )
        )
        self.gateway.register(
            ToolSpec(
                name=LIST_ACTION,
                required_capability=READ_CAPABILITY,
                required_scope=READ_CAPABILITY,
                resource_kind="workspace",
                risk_level="low",
                executor=self._list_executor,
            )
        )
        self.gateway.register(
            ToolSpec(
                name=WRITE_ACTION,
                required_capability=WRITE_CAPABILITY,
                required_scope=WRITE_CAPABILITY,
                resource_kind="workspace",
                risk_level="low",
                executor=self._write_executor,
            )
        )
        self.dispatcher = GovernedActionDispatcher(
            self.gateway,
            authorization_token_provider=self._mint_grant,
            authorization_secret=self._authorization_secret,
            now_provider=self.now,
        )
        self.loop = AgentLoop(
            run,
            self.evidence_path,
            actor_id=actor_id,
            workspace_id=workspace_id,
            actions={
                LIST_ACTION: self._bound(LIST_ACTION),
                READ_ACTION: self._bound(READ_ACTION),
                WRITE_ACTION: self._bound(WRITE_ACTION),
            },
            observer=self.observe,
        )

    # ------------------------------------------------------------------ host

    def now(self) -> int:
        return self._now()

    def _binding_token(self, ttl_seconds: int) -> str:
        return sign_binding(
            {
                "schema_version": RUN_SCHEMA,
                "run_id": self.run.run_id,
                "actor_id": self.actor_id,
                "workspace_id": self.workspace_id,
                "expires_at": self.now() + ttl_seconds,
            },
            self._binding_secret,
        )

    def _mint_grant(self) -> str:
        """Re-authorize for this call: a grant is never reused across attempts."""
        return authorize_run(
            self._run_request,
            self._binding,
            self._policy,
            now=self.now(),
            secret=self._authorization_secret,
            grant_ttl_seconds=self._grant_ttl_seconds,
        )

    def _read_executor(self, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self._read_tool(arguments)
        return {
            "path": result.path,
            "size_bytes": result.size_bytes,
            "digest": result.digest,
            "content": result.content,
        }

    def _list_executor(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._list_tool(arguments).as_output()

    def _write_executor(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._write_tool(arguments).as_output()

    def _bound(self, action_id: str) -> Callable[[Any, str], dict[str, Any]]:
        bound = self.dispatcher.bind(action_id)

        def call(step, attempt_id):
            ordinal = self._attempts.get(step.step_id, 0) + 1
            self._attempts[step.step_id] = ordinal
            hook = self._faults.get(action_id)
            if hook is not None:
                hook(step, attempt_id, ordinal)
            return bound(step, attempt_id)

        return call

    def register(self, plan) -> None:
        """Bind plan steps to the gateway, tolerating an already-bound plan."""
        pending = [step.step_id for step in plan.steps if step.step_id not in self._registered]
        if not pending:
            return
        if len(pending) != len(plan.steps):
            raise ValueError("plan partially overlaps a registered plan")
        self.dispatcher.register_plan(plan)
        self._registered.update(pending)
        self._admitted_steps = list(plan.steps)

    # ------------------------------------------------- independent observer

    def _host_state(self, path: object) -> tuple[str, bytes | None]:
        """Read the world directly; never through the tool the step used."""
        try:
            parts = _relative_parts(path)
        except ValueError:
            return "invalid", None
        candidate = os.path.realpath(os.path.join(self.workspace_root, *parts))
        if not candidate.startswith(str(self.workspace_root) + os.sep):
            return "invalid", None
        if not os.path.isfile(candidate):
            return "missing", None
        try:
            with open(candidate, "rb") as handle:
                return "file", handle.read(self._max_read_bytes + 1)
        except OSError:
            return "invalid", None

    def _host_listing(self, prefix: object, *, max_depth: int, max_entries: int) -> tuple[str, tuple[dict[str, Any], ...], bool]:
        """Independent metadata-only directory listing for postconditions."""
        try:
            parts = _relative_parts(prefix) if prefix else []
            if type(max_depth) is not int or not 1 <= max_depth <= 8:
                return "invalid", (), False
            if type(max_entries) is not int or not 1 <= max_entries <= 512:
                return "invalid", (), False
        except ValueError:
            return "invalid", (), False
        base = self.workspace_root.joinpath(*parts)
        resolved = Path(os.path.realpath(base))
        if not resolved.is_relative_to(self.workspace_root) or not resolved.is_dir():
            return "invalid", (), False
        entries: list[dict[str, Any]] = []

        def walk(directory: Path, current: str, depth: int) -> bool:
            try:
                names = sorted(directory.iterdir(), key=lambda item: item.name)
            except OSError:
                return False
            for item in names:
                if item.is_symlink():
                    continue
                if item.is_dir():
                    kind, size = "directory", None
                elif item.is_file():
                    kind, size = "file", item.stat().st_size
                else:
                    continue
                path = item.name if not current else f"{current}/{item.name}"
                if len(entries) >= max_entries:
                    return True
                entries.append({"path": path, "kind": kind, "size_bytes": size})
                if kind == "directory" and depth < max_depth and walk(item, path, depth + 1):
                    return True
            return False

        truncated = walk(resolved, prefix or "", 1)
        return "ok", tuple(entries), truncated

    def _check(self, name: str, payload: dict[str, Any]) -> tuple[str, str | None]:
        if name == "listing_ok":
            status, entries, truncated = self._host_listing(
                payload.get("prefix"),
                max_depth=payload.get("max_depth"),
                max_entries=payload.get("max_entries"),
            )
            if status != "ok":
                return "unknown", None
            canonical = json.dumps(
                {"entries": list(entries), "prefix": payload.get("prefix", ""), "truncated": truncated},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return "verified", _digest_bytes(canonical)
        path = payload.get("path")
        state, raw = self._host_state(path)
        if name == "read_ok":
            if state == "missing":
                return "absent", None
            if state == "invalid" or raw is None:
                return "unknown", None
            return "verified", _digest_bytes(raw)
        if name in {"file_present", "content_matches_payload"}:
            if state == "missing":
                return "absent", None
            if state == "invalid" or raw is None:
                return "unknown", None
            if name == "file_present":
                return "verified", _digest_bytes(raw)
            content = payload.get("content")
            if not isinstance(content, str):
                return "unknown", None
            if _digest_bytes(raw) == _digest_bytes(content.encode("utf-8")):
                return "verified", _digest_bytes(raw)
            return "absent", _digest_bytes(raw)
        if name == "file_absent":
            if state == "missing":
                return "verified", None
            if state == "invalid":
                return "unknown", None
            return "absent", _digest_bytes(raw or b"")
        return "unknown", None

    def observe(self, step, attempt_id: str) -> PostconditionResult:
        if self._observer_hook is not None:
            ordinal = self._observations.get(step.step_id, 0) + 1
            self._observations[step.step_id] = ordinal
            injected = self._observer_hook(step, attempt_id, ordinal)
            if injected is not None:
                if not isinstance(injected, PostconditionResult):
                    raise ValueError("observer_hook must return a PostconditionResult or None")
                return injected
        verdicts = [self._check(name, step.input_payload) for name in step.expected_postconditions]
        if not verdicts:
            return PostconditionResult("unknown", "no_postcondition")
        if any(verdict == "unknown" for verdict, _ in verdicts):
            return PostconditionResult("unknown", "postcondition_unknown")
        observed = next((digest for _, digest in verdicts if digest), None)
        if all(verdict == "verified" for verdict, _ in verdicts):
            return PostconditionResult("verified", "postcondition_met", observed)
        return PostconditionResult("absent", "effect_not_present", observed)

    def verify_expectations(
        self, artifacts: tuple[ExpectedArtifact, ...] | list[ExpectedArtifact] = ()
    ) -> DeliverableVerification:
        """Host-owned final check; the plan and the loop state are not evidence."""
        checked: list[str] = []
        failures: list[str] = []
        undecided = False
        for artifact in artifacts:
            checked.append(artifact.path)
            state, raw = self._host_state(artifact.path)
            if artifact.absent:
                if state == "file":
                    failures.append(f"{artifact.path}:unexpected_file")
                elif state == "invalid":
                    undecided = True
                continue
            if state == "missing":
                failures.append(f"{artifact.path}:missing")
                continue
            if state == "invalid" or raw is None:
                undecided = True
                continue
            if artifact.content is not None:
                if raw != artifact.content.encode("utf-8"):
                    failures.append(f"{artifact.path}:content_mismatch")
                continue
            if artifact.contains is not None:
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    undecided = True
                    continue
                missing = [item for item in artifact.contains if item not in text]
                if missing:
                    failures.append(f"{artifact.path}:missing_text:{','.join(missing)}")
                continue
            if _digest_bytes(raw) != artifact.digest:
                failures.append(f"{artifact.path}:digest_mismatch")
        if failures:
            verdict = "failed"
        elif undecided:
            verdict = "unknown"
        else:
            verdict = "verified"
        return DeliverableVerification(verdict, tuple(checked), tuple(failures))

    # ------------------------------------------------------------- the entry

    def plan_format(self) -> dict[str, Any]:
        """The exact envelope the model must echo, with host-owned identity.

        Identity is not delegated: the model copies these values verbatim and
        admission rejects any mismatch. Publishing the shape here is what makes
        a real model able to produce an admissible plan at all.
        """
        return {
            "schema_version": "northstar.agent-plan.v1",
            "envelope_fields": {
                "schema_version": "northstar.agent-plan.v1",
                "plan_id": "any identifier you choose, unique per plan",
                "plan_version": "positive integer, 1 for the first plan",
                "task_id": self.run.task_id,
                "thread_id": self.run.thread_id,
                "run_id": self.run.run_id,
                "actor_id": self.actor_id,
                "workspace_id": self.workspace_id,
                "policy_revision": self.policy_revision,
                "trace_id": self.run.trace_id,
                "steps": "non-empty array of at most 64 step objects",
            },
            "step_fields": {
                "schema_version": "northstar.agent-plan-step.v1",
                "step_id": "identifier, unique inside the plan",
                "action_id": "one of the action ids listed in actions",
                "input_payload": "object with exactly the payload_fields of that action",
                "scope_snapshot": "non-empty subset of the run scope",
                "expected_postconditions": "non-empty subset of that action's postconditions",
                "idempotency_key": "identifier, unique inside the plan",
                "max_attempts": "integer 1..3",
                "deadline_at": f"integer, at most {self.run.deadline_at}",
            },
            "rules": [
                "Return JSON with exactly one top-level key, plan.",
                "Copy every host identity value verbatim; do not invent or change one.",
                "Plan only steps that the listed actions can perform; you cannot run commands or reach the network.",
                "deadline_at must not exceed the run deadline.",
            ],
        }

    def workspace_inventory(self, *, limit: int = 64, max_depth: int = 4) -> tuple[dict[str, Any], ...]:
        """Bounded host-side inventory of the agent's own sandbox.

        A planner that cannot see which files exist can only guess names, and a
        guessed name is rejected by the tool boundary anyway. Names and sizes
        only: content still requires a read step, so the inventory never becomes
        a shortcut around the tools.
        """
        if not 1 <= limit <= 512 or not 1 <= max_depth <= 8:
            raise ValueError("inventory bounds are invalid")
        root = self.workspace_root
        entries: list[dict[str, Any]] = []
        for directory, subdirectories, names in os.walk(root, followlinks=False):
            subdirectories[:] = sorted(
                name
                for name in subdirectories
                if not os.path.islink(os.path.join(directory, name))
                and directory[len(str(root)):].count(os.sep) < max_depth
            )
            for name in sorted(names):
                absolute = os.path.join(directory, name)
                if os.path.islink(absolute) or not os.path.isfile(absolute):
                    continue
                entries.append(
                    {
                        "path": os.path.relpath(absolute, root),
                        "size_bytes": os.path.getsize(absolute),
                    }
                )
                if len(entries) >= limit:
                    return tuple(entries)
        return tuple(entries)

    def planner_context(self, *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Everything the planner legitimately needs: identity, budget, tools.

        Every field an admissible plan must echo is published here; nothing the
        model returns is trusted, and admission still rejects any mismatch.
        Round state (observations, feedback) is merged at the top level so a
        model reads one flat context, and host fields cannot be overridden.
        """
        context = {
            "task_id": self.run.task_id,
            "thread_id": self.run.thread_id,
            "run_id": self.run.run_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "trace_id": self.run.trace_id,
            "now": self.now(),
            "deadline_at": self.run.deadline_at,
            "policy_revision": self.policy_revision,
            "scope": list(self.run.scope_snapshot),
            "workspace_files": [dict(entry) for entry in self.workspace_inventory()],
            "plan_format": self.plan_format(),
            "actions": [
                {
                    "action_id": LIST_ACTION,
                    "payload_fields": ["prefix", "max_depth", "max_entries"],
                    "postconditions": ["listing_ok"],
                },
                {
                    "action_id": READ_ACTION,
                    "payload_fields": ["path", "max_bytes"],
                    "postconditions": ["read_ok", "file_present"],
                },
                {
                    "action_id": WRITE_ACTION,
                    "payload_fields": ["path", "content"],
                    "postconditions": [
                        "content_matches_payload",
                        "file_present",
                        "file_absent",
                    ],
                },
            ],
            "workspace_boundary": "host-owned root; relative paths only; no network",
        }
        for key, value in (extra or {}).items():
            if key in context:
                raise ValueError(f"round context cannot override host field {key}")
            context[key] = value
        return context

    def admitted_steps(self) -> tuple[Any, ...]:
        """Steps this harness admitted, in plan order (read-only for the driver)."""
        return tuple(self._admitted_steps)

    def inspect_listing(self, prefix: str, *, max_depth: int, max_entries: int) -> dict[str, Any]:
        status, entries, truncated = self._host_listing(
            prefix, max_depth=max_depth, max_entries=max_entries
        )
        return {
            "state": status,
            "prefix": prefix,
            "entries": [dict(entry) for entry in entries],
            "truncated": truncated,
        }

    def inspect(self, path: str, *, limit: int = 2_048) -> dict[str, Any]:
        """Bounded host-side view of one workspace path, independent of tools.

        The driver re-plans from these observations, so they must come from the
        filesystem rather than from a tool's claimed output. Content is dropped
        when it does not fit, and never trusted as a verification result.
        """
        state, raw = self._host_state(path)
        observation: dict[str, Any] = {"state": state, "digest": None, "size_bytes": None}
        if raw is not None:
            observation["digest"] = _digest_bytes(raw)
            observation["size_bytes"] = len(raw)
            observation["truncated"] = len(raw) > limit
            if len(raw) <= limit:
                try:
                    observation["content"] = raw.decode("utf-8")
                except UnicodeDecodeError:
                    observation["content"] = None
                    observation["encoding"] = "binary"
        return observation

    def evidence_events(self) -> int:
        if not self.evidence_path.exists():
            return 0
        with self.evidence_path.open("rb") as handle:
            return sum(1 for line in handle if line.strip())

    def run_goal(
        self,
        goal: str,
        planner,
        *,
        expectations: tuple[ExpectedArtifact, ...] | list[ExpectedArtifact] = (),
        context: dict[str, Any] | None = None,
    ) -> TaskOutcome:
        """Plan, execute, recover within bound, then verify the deliverable."""
        generated = planner.generate(
            goal,
            context=self.planner_context(extra=context),
            loop=self.loop,
            current_policy_revision=self.policy_revision,
            owner_id=self.actor_id,
            now=self.now(),
        )
        plan = generated.candidate
        self.register(plan)
        state = self.loop.run(
            plan,
            owner_id=self.actor_id,
            now=self.now(),
            current_policy_revision=self.policy_revision,
        )
        resumes = 0
        while state.status == "paused_unknown" and resumes < self.max_resumes:
            resumes += 1
            state = self.loop.resume(
                plan,
                owner_id=self.actor_id,
                now=self.now(),
                current_policy_revision=self.policy_revision,
            )
        verification = self.verify_expectations(expectations)
        steps = tuple(
            StepOutcome(
                step_id=step.step_id,
                action_id=step.action_id,
                status=state.steps[step.step_id]["status"],
                reason_code=state.steps[step.step_id].get("reason_code"),
                attempts=state.steps[step.step_id]["attempt"],
            )
            for step in plan.steps
            if step.step_id in state.steps
        )
        return TaskOutcome(
            task_id=self.run.task_id,
            goal=goal,
            run_status=state.status,
            verification=verification,
            steps=steps,
            planner_attempts=generated.attempts,
            resumes=resumes,
            evidence_events=self.evidence_events(),
        )


def _steps_plan(steps: list[dict[str, Any]], run: RunContract, *, actor_id: str, workspace_id: str,
                policy_revision: str, task_id: str) -> dict[str, Any]:
    """Wrap host-supplied steps into a plan carrying host-owned identity."""
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": f"plan-{task_id}",
        "plan_version": 1,
        "task_id": run.task_id,
        "thread_id": run.thread_id,
        "run_id": run.run_id,
        "actor_id": actor_id,
        "workspace_id": workspace_id,
        "policy_revision": policy_revision,
        "trace_id": run.trace_id,
        "steps": steps,
    }


class _PlanFileCaller:
    """Adapter-compatible caller that replays a host-supplied plan file."""

    def __init__(self, plan: dict[str, Any]):
        self.plan = plan

    def __call__(self, *, goal, context, repair_error, attempt):
        from planner_adapter import PlannerModelResponse

        return PlannerModelResponse(
            {"plan": self.plan}, "host-plan-file", "host", "rev-1"
        )


def main(argv=None) -> int:
    """Run one goal from a host-supplied step file. No model call is made."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Run one local agent task from a plan file.")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--goal", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--steps", required=True, help="JSON file with a list of plan steps")
    parser.add_argument("--expect", default=None, help="JSON file with expected artifacts")
    parser.add_argument("--evidence", default=None)
    parser.add_argument("--actor-id", default=None)
    parser.add_argument("--workspace-id", default=None)
    arguments = parser.parse_args(argv)

    run = build_run(arguments.task_id)
    actor_id = arguments.actor_id or f"actor-{arguments.task_id}"
    workspace_id = arguments.workspace_id or f"workspace-{arguments.task_id}"
    evidence = arguments.evidence or str(Path(arguments.workspace) / "agent-evidence.jsonl")
    steps = json.loads(Path(arguments.steps).read_text(encoding="utf-8"))
    if not isinstance(steps, list) or not steps:
        raise ValueError("step file must contain a non-empty list")
    expects = []
    if arguments.expect:
        expects = [
            ExpectedArtifact(
                path=item["path"],
                content=item.get("content"),
                digest=item.get("digest"),
                absent=bool(item.get("absent", False)),
            )
            for item in json.loads(Path(arguments.expect).read_text(encoding="utf-8"))
        ]
    harness = AgentHarness(
        run, arguments.workspace, evidence, actor_id=actor_id, workspace_id=workspace_id
    )
    from planner_adapter import TypedPlannerAdapter

    plan = _steps_plan(
        steps,
        run,
        actor_id=actor_id,
        workspace_id=workspace_id,
        policy_revision=harness.policy_revision,
        task_id=arguments.task_id,
    )
    outcome = harness.run_goal(
        arguments.goal, TypedPlannerAdapter(_PlanFileCaller(plan)), expectations=expects
    )
    print(json.dumps(outcome.as_dict(), indent=2))
    return 0 if outcome.ok else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
