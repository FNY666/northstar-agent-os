"""The governed agent loop: reasoning here, policy enforced here, execution delegated.

This is the whole runtime contract in one file. Read it as a set of guarantees:

* **Exactly one** :class:`~providers.base.ResultMessage` per run, and every
  expected failure is reported as one - a denied tool, an exhausted script, a
  provider outage, a hook veto - never as a raised exception.
* **Three independent ceilings**: ``max_turns``, ``max_tool_calls``,
  ``max_budget_usd``, each with its own result subtype, so "the model would not
  stop" and "the model would not stop paying" are distinguishable afterwards.
* **Ten hooks** with terminal deny; the permission gate behind them; the tool
  sandbox behind that.
* **Compaction only at a safe boundary**, so a summarized transcript can never
  present an orphaned ``tool_use`` to the API.
* **Delegation as a governed child run**: own transcript, declared tool subset
  gated per tool, own ceilings, cost rolled up into the parent.

The loop holds no model credentials of its own beyond what the injected provider
carries, and it never spawns a model CLI: Codex execution goes to
``components/northstar-codex-sidecar`` over a Unix socket via the ``CodexReadOnly``
tool, which is registered only when a socket path is supplied.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from agents import AgentDefinition, AgentRegistry, Verdict, builtin_registry, parse_verdict
from budget import Budget
from compaction import CompactionOutcome, compact, should_compact
from hooks import HookInput, HookRegistry
from permissions import (
    DelegationVerdict,
    PermissionConfig,
    PermissionDecision,
    PermissionEngine,
    PermissionMode,
    PermissionRequestContext,
    normalise_names,
)
from providers.base import (
    AssistantMessage,
    Generation,
    GenerationRequest,
    Message,
    SystemMessage,
    ResultMessage,
    ToolResultBlock,
    ToolUseBlock,
    Usage,
    UserMessage,
    estimate_transcript_tokens,
    render_transcript,
    transcript_to_api,
)
from sessions import SessionStore, resolve_session_id
from sidecar_client import SIDECAR_MAX_TIMEOUT_MS, SIDECAR_MIN_TIMEOUT_MS, SidecarClient
from tools import (
    ToolAccessError,
    ToolContext,
    ToolInputError,
    ToolLimits,
    ToolRegistry,
    ToolResult,
    ToolSpec,
    ToolSandbox,
    build_default_registry,
    codex_tool_spec,
)
from tracing import Tracer

TASK_TOOL_NAME = "Task"
DEFAULT_MODEL = "claude-sonnet-4-5"
DEFAULT_MAX_TURNS = 25
DEFAULT_MAX_TOOL_CALLS = 50
DEFAULT_COMPACTION_THRESHOLD_TOKENS = 60_000

DEFAULT_SYSTEM_PROMPT = (
    "You are a Northstar Agent OS coworker running inside a governed runtime.\n"
    "The tools you can see are the tools that exist: a refusal is a policy decision made "
    "outside you, so report it instead of working around it.\n"
    "Read before you write. Prefer the narrowest tool call that answers the question. "
    "When a task needs broad investigation, delegate it to a subagent with an explicit "
    "prompt rather than reading the repository one file at a time.\n"
    "Finish with a short report: what you did, what you verified, what you did not verify."
)


class RuntimeConfigurationError(ValueError):
    """Invalid configuration. Raised at construction, never mid-run."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Everything the loop enforces. Constructed, validated, then frozen."""

    model: str = DEFAULT_MODEL
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    max_turns: int = DEFAULT_MAX_TURNS
    max_tool_calls: int | None = DEFAULT_MAX_TOOL_CALLS
    max_budget_usd: float | None = None
    permission_mode: PermissionMode = "default"
    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()
    workspace: str | None = None
    session_id: str | None = None
    agent: str = "main"
    depth: int = 0
    allow_delegation: bool = True
    max_subagent_depth: int = 1
    allow_nested_delegation: bool = False
    default_subagent: str = "explorer"
    halt_on_denial: bool = False
    max_output_tokens: int = 4096
    compaction_threshold_tokens: int | None = DEFAULT_COMPACTION_THRESHOLD_TOKENS
    compaction_keep_messages: int = 4
    tool_limits: ToolLimits = field(default_factory=ToolLimits)
    sidecar_socket: str | None = None
    sidecar_timeout_ms: int = 30_000
    include_describe_tool: bool = True
    record_tool_output_in_session: bool = True

    def __post_init__(self) -> None:
        def fail(message: str) -> None:
            raise RuntimeConfigurationError(message)

        if not isinstance(self.model, str) or not self.model.strip():
            fail("model must be a non-empty string")
        if isinstance(self.max_turns, bool) or not isinstance(self.max_turns, int) or self.max_turns < 1:
            fail("max_turns must be an integer >= 1")
        if self.max_tool_calls is not None:
            if isinstance(self.max_tool_calls, bool) or not isinstance(self.max_tool_calls, int) or self.max_tool_calls < 0:
                fail("max_tool_calls must be a non-negative integer or None")
        if self.max_budget_usd is not None:
            if isinstance(self.max_budget_usd, bool) or not isinstance(self.max_budget_usd, (int, float)):
                fail("max_budget_usd must be a number or None")
            elif self.max_budget_usd <= 0:
                fail("max_budget_usd must be positive when set; use None for no ceiling")
        if self.compaction_threshold_tokens is not None:
            if isinstance(self.compaction_threshold_tokens, bool) or not isinstance(self.compaction_threshold_tokens, int):
                fail("compaction_threshold_tokens must be an integer or None")
            elif self.compaction_threshold_tokens < 512:
                fail("compaction_threshold_tokens must be >= 512 or None to disable")
        if self.compaction_keep_messages < 1:
            fail("compaction_keep_messages must keep at least one message")
        if self.max_output_tokens < 1:
            fail("max_output_tokens must be positive")
        if self.depth < 0:
            fail("depth must not be negative")
        if self.max_subagent_depth < 0:
            fail("max_subagent_depth must be >= 0 (0 disables delegation)")
        if not SIDECAR_MIN_TIMEOUT_MS <= int(self.sidecar_timeout_ms) <= SIDECAR_MAX_TIMEOUT_MS:
            fail(
                f"sidecar_timeout_ms must be between {SIDECAR_MIN_TIMEOUT_MS} and {SIDECAR_MAX_TIMEOUT_MS}"
            )
        object.__setattr__(self, "allowed_tools", normalise_names(self.allowed_tools))
        object.__setattr__(self, "disallowed_tools", normalise_names(self.disallowed_tools))

    @property
    def budget_enabled(self) -> bool:
        return self.max_budget_usd is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "max_turns": self.max_turns,
            "max_tool_calls": self.max_tool_calls,
            "max_budget_usd": self.max_budget_usd,
            "permission_mode": self.permission_mode,
            "allowed_tools": list(self.allowed_tools),
            "disallowed_tools": list(self.disallowed_tools),
            "workspace": self.workspace,
            "agent": self.agent,
            "depth": self.depth,
            "allow_delegation": self.allow_delegation,
            "max_subagent_depth": self.max_subagent_depth,
            "allow_nested_delegation": self.allow_nested_delegation,
            "halt_on_denial": self.halt_on_denial,
            "compaction_threshold_tokens": self.compaction_threshold_tokens,
            "sidecar": bool(self.sidecar_socket),
        }


@dataclass(frozen=True)
class Denial:
    """One refused action, kept for the result message and the session log."""

    tool: str = ""
    source: str = ""
    reason: str = ""
    agent: str = "main"
    turn_index: int = 0
    kind: str = "tool"

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "source": self.source,
            "reason": self.reason,
            "agent": self.agent,
            "turn_index": self.turn_index,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class ToolCallReport:
    """Per-call bookkeeping: what ran, who allowed it, how it ended."""

    name: str = ""
    call_id: str = ""
    is_error: bool = False
    denied: bool = False
    permission_source: str = ""
    duration_ms: int = 0
    result_chars: int = 0
    truncated: bool = False
    input_rewritten: bool = False
    turn_index: int = 0
    agent: str = "main"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "call_id": self.call_id,
            "is_error": self.is_error,
            "denied": self.denied,
            "permission_source": self.permission_source,
            "duration_ms": self.duration_ms,
            "result_chars": self.result_chars,
            "truncated": self.truncated,
            "input_rewritten": self.input_rewritten,
            "turn_index": self.turn_index,
            "agent": self.agent,
        }


@dataclass(frozen=True)
class SubagentReport:
    """What a delegated child run did, as the parent saw it."""

    agent: str = ""
    result: ResultMessage | None = None
    turns: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0
    usage: Usage = field(default_factory=Usage)
    verdict: Verdict | None = None
    final_text: str = ""
    denials: tuple[Denial, ...] = ()
    transcript: str = ""
    permission_verdict: DelegationVerdict | None = None
    depth: int = 1

    @property
    def subtype(self) -> str:
        return self.result.subtype if self.result is not None else "error_during_execution"

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "subtype": self.subtype,
            "turns": self.turns,
            "tool_calls": self.tool_calls,
            "cost_usd": self.cost_usd,
            "usage": self.usage.as_dict(),
            "verdict": self.verdict.as_dict() if self.verdict else None,
            "denials": [denial.as_dict() for denial in self.denials],
            "final_text_chars": len(self.final_text),
            "permission_gate": self.permission_verdict.as_dict() if self.permission_verdict else None,
            "depth": self.depth,
        }


@dataclass(frozen=True)
class RunReport:
    """Everything a caller gets back from :meth:`AgentRuntime.run_collect`."""

    events: tuple[Message, ...] = ()
    result: ResultMessage | None = None
    transcript: tuple[Message, ...] = ()
    denials: tuple[Denial, ...] = ()
    tool_calls: tuple[ToolCallReport, ...] = ()
    subagents: tuple[SubagentReport, ...] = ()
    compactions: tuple[dict[str, Any], ...] = ()
    hook_fires: tuple[dict[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    session_id: str = ""
    spans: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.result is not None and not self.result.is_error

    @property
    def subtype(self) -> str:
        return self.result.subtype if self.result is not None else "error_during_execution"

    @property
    def final_text(self) -> str:
        for message in reversed(self.transcript):
            if isinstance(message, AssistantMessage) and message.text:
                return message.text
        return ""

    @property
    def assistant_texts(self) -> tuple[str, ...]:
        return tuple(
            message.text
            for message in self.transcript
            if isinstance(message, AssistantMessage) and message.text
        )

    @property
    def cost_usd(self) -> float:
        return self.result.total_cost_usd if self.result is not None else 0.0

    def events_of(self, kind: type) -> tuple[Any, ...]:
        return tuple(event for event in self.events if isinstance(event, kind))

    @property
    def compact_boundaries(self) -> tuple[SystemMessage, ...]:
        return tuple(
            event
            for event in self.events
            if isinstance(event, SystemMessage) and event.subtype == "compact_boundary"
        )

    @property
    def trace(self) -> str:
        return self._trace

    def as_dict(self) -> dict[str, Any]:
        result = self.result
        return {
            "session_id": self.session_id,
            "subtype": self.subtype,
            "turns": result.num_turns if result else 0,
            "tool_calls": len(self.tool_calls),
            "denials": [denial.as_dict() for denial in self.denials],
            "subagents": [report.as_dict() for report in self.subagents],
            "compactions": list(self.compactions),
            "errors": list(self.errors),
            "cost_usd": result.total_cost_usd if result else 0.0,
            "pricing_estimated": result.pricing_estimated if result else False,
        }

    _trace: str = ""


@dataclass
class _RunState:
    """Mutable per-run bookkeeping."""

    session_id: str
    transcript: list[Any] = field(default_factory=list)
    turns: int = 0
    tool_calls: int = 0
    denials: list[Denial] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    subagents: list[SubagentReport] = field(default_factory=list)
    tool_reports: list[ToolCallReport] = field(default_factory=list)
    compactions: list[dict[str, Any]] = field(default_factory=list)
    hook_fires: list[dict[str, Any]] = field(default_factory=list)
    final_text: str = ""
    started: float = field(default_factory=time.monotonic)
    result: ResultMessage | None = None
    stop_blocks: int = 0
    session_end_fired: bool = False
    events: list[Any] = field(default_factory=list)


class AgentRuntime:
    """One configured governed loop."""

    def __init__(
        self,
        *,
        provider: Any,
        config: RuntimeConfig | None = None,
        tools: ToolRegistry | None = None,
        hooks: HookRegistry | None = None,
        agents: AgentRegistry | None = None,
        permissions: PermissionEngine | None = None,
        can_use_tool: Callable[[str, dict[str, Any], PermissionRequestContext], Any] | None = None,
        tracer: Tracer | None = None,
        sessions: SessionStore | None = None,
        providers: Mapping[str, Any] | None = None,
        sidecar: SidecarClient | None = None,
        budget: Budget | None = None,
        summarizer: Callable[[Sequence[Any]], str] | None = None,
    ) -> None:
        if provider is None:
            raise RuntimeConfigurationError("a provider is required")
        self.config = config or RuntimeConfig()
        self.provider = provider
        self.providers: dict[str, Any] = dict(providers or {})
        self.hooks = hooks if isinstance(hooks, HookRegistry) else HookRegistry()
        self.agents = agents if isinstance(agents, AgentRegistry) else builtin_registry()
        self.tracer = tracer if isinstance(tracer, Tracer) else Tracer(collect=True)
        self.sessions = sessions if isinstance(sessions, SessionStore) else SessionStore(None, session_id=self.config.session_id)
        self.summarizer = summarizer
        self.sandbox = ToolSandbox(self.config.workspace or ".", limits=self.config.tool_limits)
        self.limits = self.config.tool_limits
        self.budget = budget if isinstance(budget, Budget) else Budget(max_budget_usd=self.config.max_budget_usd)
        self.tools = tools if isinstance(tools, ToolRegistry) else build_default_registry(include_describe=self.config.include_describe_tool)
        # The sidecar is the only execution path this runtime knows about, and it
        # exists only when the host handed over a socket.
        self.sidecar = sidecar
        if self.sidecar is None and self.config.sidecar_socket:
            self.sidecar = SidecarClient(
                self.config.sidecar_socket,
                timeout_ms=int(self.config.sidecar_timeout_ms),
            )
        if self.sidecar is not None and "CodexReadOnly" not in self.tools:
            self.tools.register(codex_tool_spec())
        if self.config.allow_delegation and self._delegation_allowed(self.config.depth):
            self.tools.register(task_tool_spec(), replace_existing=True)
        else:
            self.tools.unregister(TASK_TOOL_NAME)
        self.permissions = permissions or PermissionEngine(
            PermissionConfig(
                mode=self.config.permission_mode,
                allowed_tools=self.config.allowed_tools,
                disallowed_tools=self.config.disallowed_tools,
                can_use_tool=can_use_tool,
            )
        )
        if can_use_tool is not None and self.permissions.config.can_use_tool is None:
            self.permissions = PermissionEngine(replace(self.permissions.config, can_use_tool=can_use_tool))
        for spec in self.tools.specs():
            if not self.permissions.knows(spec.name):
                self.permissions.register_kind(spec.name, spec.kind)
        self.session_id = resolve_session_id(self.config.session_id, self.sessions if self.sessions.enabled else None)
        if self.sessions.session_id != self.session_id:
            self.sessions = replace(self.sessions, session_id=self.session_id)
        #: Last finished run, kept so ``run_collect`` and subagent delegation can
        #: read a full report without re-deriving it from events.
        self._pending_state: _RunState | None = None
        self._last_report: RunReport | None = None

    # -- capability views --------------------------------------------------
    @property
    def provider_name(self) -> str:
        return getattr(self.provider, "name", type(self.provider).__name__)

    @property
    def durable(self) -> bool:
        return self.sessions.enabled

    @property
    def last_report(self) -> RunReport | None:
        """Report for the most recent run this instance executed (or is running)."""
        if self._last_report is not None:
            return self._last_report
        if self._pending_state is not None:
            return self._report(self._pending_state.events, state=self._pending_state)
        return None

    def _delegation_allowed(self, depth: int) -> bool:
        if not self.config.allow_delegation:
            return False
        if self.config.max_subagent_depth <= 0:
            return False
        return depth < self.config.max_subagent_depth

    def tool_names(self) -> tuple[str, ...]:
        return self.tools.names()

    def api_tools(self) -> tuple[dict[str, Any], ...]:
        return self.tools.to_api()

    def describe(self) -> dict[str, Any]:
        return {
            "config": self.config.as_dict(),
            "provider": self.provider_name,
            "tools": self.tools.describe(),
            "agents": self.agents.describe(),
            "hooks": self.hooks.counts(),
            "session_id": self.session_id,
            "session_store": "jsonl" if self.sessions.enabled else "none",
            "workspace": str(self.sandbox.root_real),
        }

    def pricing(self) -> dict[str, Any]:
        from budget import price_for

        pricing, estimated = price_for(self.config.model)
        return {"model": self.config.model, **pricing.as_dict(), "estimated": estimated}

    # -- public entry points ----------------------------------------------
    def run(self, prompt: str, *, resume: Sequence[Any] | None = None) -> Iterator[Message]:
        """Stream events for one run. Terminates in exactly one ResultMessage."""
        state = _RunState(session_id=self.session_id)
        if resume:
            state.transcript.extend(resume)
        self._pending_state = state
        self._last_report = None
        # A subagent's run hangs off the span its parent opened for it, so the
        # trace is one tree rather than a pile of roots.
        parent_span = self.tracer.open_spans[-1] if self.tracer.open_spans else None
        run_span = self.tracer.start_span(
            "run",
            parent=parent_span,
            attributes={
                "session.id": state.session_id,
                "agent.name": self.config.agent,
                "agent.depth": self.config.depth,
                "model": self.config.model,
                "provider": self.provider_name,
                "permission.mode": self.permissions.mode,
                "limits.max_turns": self.config.max_turns,
                "tools.count": len(self.tools),
                "workspace.root": str(self.sandbox.root_real)[: self.tracer.max_attribute_chars],
            },
        )
        state.result = None
        finished = False
        try:
            for event in self._events(prompt, state, run_span):
                state.events.append(event)
                if isinstance(event, ResultMessage):
                    finished = True
                yield event
            if state.result is not None and not finished:
                finished = True
                yield state.result
        except Exception as error:  # noqa: BLE001 - every expected failure is an event
            state.errors.append(f"unexpected runtime failure: {type(error).__name__}: {error}")
            run_span.record_error(f"{type(error).__name__}: {error}")
            if state.result is None:
                state.result = self._result(state, "error_during_execution")
                if not finished:
                    finished = True
                    yield state.result
        finally:
            self._close_run(state, run_span)

    def run_collect(self, prompt: str, *, resume: Sequence[Any] | None = None) -> RunReport:
        events = tuple(self.run(prompt, resume=resume))
        state = self._pending_state
        if state is None:  # pragma: no cover - defensive
            return RunReport(events=events)
        return self._report(state.events, state=state)

    # -- the loop ----------------------------------------------------------
    def _events(self, prompt: str, state: _RunState, run_span: Any) -> Iterator[Message]:
        config = self.config
        if not isinstance(prompt, str) or not prompt.strip():
            state.errors.append("prompt must be non-empty text")
            yield self._finish(state, "error_during_execution")
            return

        init_data = {
            "session_id": state.session_id,
            "provider": self.provider_name,
            "model": config.model,
            "permission_mode": self.permissions.mode,
            "allowed_tools": list(config.allowed_tools),
            "disallowed_tools": list(config.disallowed_tools),
            "tools": list(self.tools.names()),
            "subagents": list(self.agents.names()),
            "hooks": self.hooks.counts(),
            "sidecar": bool(self.sidecar),
            "limits": {
                "max_turns": config.max_turns,
                "max_tool_calls": config.max_tool_calls,
                "max_budget_usd": config.max_budget_usd,
                "max_subagent_depth": config.max_subagent_depth,
                # None means compaction is off; a host that passed a threshold on
                # the command line can confirm the number that took effect.
                "compaction_threshold_tokens": config.compaction_threshold_tokens,
            },
            "depth": config.depth,
            "workspace": str(self.sandbox.root_real),
        }
        init = SystemMessage(subtype="init", content=f"runtime ready: {self.provider_name}/{config.model}", data=init_data)
        self.sessions.record_system(init, agent=config.agent)
        yield init

        # SessionStart may seed context or refuse the run outright.
        start = self._fire(state, "SessionStart", HookInput(event="SessionStart", session_id=state.session_id, agent=config.agent, depth=config.depth, data={"model": config.model, "tools": list(self.tools.names())}))
        if start.denied:
            state.denials.append(Denial(tool="", source="hook:SessionStart", reason=start.deny_reason, agent=config.agent, kind="run"))
            yield self._finish(state, "error_permission_denied")
            return
        for context in (start.additional_context,):
            if context:
                note = SystemMessage(subtype="informational", content=context)
                state.transcript.append(note)
                self.sessions.record_system(note, agent=config.agent)
                yield note

        submitted = self._fire(
            state,
            "UserPromptSubmit",
            HookInput(event="UserPromptSubmit", session_id=state.session_id, agent=config.agent, depth=config.depth, prompt=prompt, turn_index=0),
        )
        if submitted.denied:
            state.denials.append(
                Denial(source="hook:UserPromptSubmit", reason=submitted.deny_reason, agent=config.agent, turn_index=0, kind="prompt")
            )
            yield self._finish(state, "error_permission_denied")
            return
        for context in submitted.additional_context:
            if context:
                note = SystemMessage(subtype="informational", content=context)
                state.transcript.append(note)
                self.sessions.record_system(note, agent=config.agent)
                yield note

        user = UserMessage.text_block(prompt)
        state.transcript.append(user)
        self.sessions.append("user_prompt", {"agent": config.agent, "role": "user", "content": [block.to_api() for block in user.content]})

        for turn_index in range(1, config.max_turns + 1):
            # Ceilings are checked before spending, never after.
            stop = self._ceiling_stop(state)
            if stop is not None:
                yield self._finish(state, stop)
                return
            if should_compact(state.transcript, config.compaction_threshold_tokens):
                outcome = self._compact(state, turn_index=turn_index)
                if outcome.performed and outcome.boundary is not None:
                    state.transcript = list(outcome.transcript)
                    self.sessions.append(
                        "compact_boundary",
                        {"agent": config.agent, "subtype": "compact_boundary", "content": outcome.summary, "data": outcome.as_dict()},
                    )
                    yield outcome.boundary

            state.cost_at_turn_start = self.budget.total_cost_usd
            with run_span.child(f"turn[{turn_index}]") as turn_span:
                turn_span.set_attributes({"turn.index": turn_index, "turn.depth": config.depth, "agent.name": config.agent})
                request = GenerationRequest(
                    system=config.system_prompt,
                    messages=tuple(transcript_to_api(state.transcript)),
                    tools=self.api_tools(),
                    model=config.model,
                    max_tokens=config.max_output_tokens,
                    agent=config.agent,
                    turn_index=turn_index,
                    depth=config.depth,
                )
                generation: Generation | None = None
                breakdown = None
                with turn_span.child("generation") as generation_span:
                    generation_span.set_attributes({"provider.name": self.provider_name, "model": config.model, "turn.index": turn_index})
                    try:
                        candidate = self.provider.generate(request)
                    except Exception as error:  # noqa: BLE001 - a provider fault is an event
                        state.errors.append(f"provider failure on turn {turn_index}: {type(error).__name__}: {error}")
                        generation_span.record_error(f"{type(error).__name__}")
                    else:
                        if not isinstance(candidate, Generation):
                            state.errors.append(f"provider returned {type(candidate).__name__} instead of a Generation")
                        else:
                            generation = candidate
                            breakdown = self.budget.observe(generation.usage, generation.model or config.model)
                            # Usage and cost are recorded while the generation span is
                            # still open. The instant it ends, OpenTelemetry discards
                            # any further attribute write silently and the cost simply
                            # goes missing from the trace with no error anywhere.
                            generation_span.record_usage(
                                generation.usage,
                                breakdown.total_usd,
                                extra={
                                    "stop_reason": generation.stop_reason,
                                    "pricing.estimated": breakdown.pricing_estimated,
                                    "pricing.source": breakdown.pricing_source,
                                    "tokens.total": generation.usage.total_tokens,
                                },
                            )
                if generation is None or breakdown is None:
                    yield self._finish(state, "error_during_execution")
                    return
                assistant = AssistantMessage(
                    content=_assign_tool_use_ids(generation.content, state),
                    model=generation.model or config.model,
                    usage=generation.usage,
                    stop_reason=generation.stop_reason,
                )
                state.transcript.append(assistant)
                state.turns += 1
                self.sessions.record_assistant(assistant, agent=config.agent)
                yield assistant

                calls = assistant.tool_uses
                if not calls:
                    stop_verdict = self._fire(
                        state,
                        "Stop",
                        HookInput(
                            event="Stop",
                            session_id=state.session_id,
                            agent=config.agent,
                            depth=config.depth,
                            turn_index=turn_index,
                            data={"transcript_messages": len(state.transcript), "final_text_chars": len(assistant.text)},
                        ),
                    )
                    if stop_verdict.blocked:
                        state.stop_blocks += 1
                        reason = stop_verdict.block_reason or "the run was not allowed to stop"
                        follow_up = UserMessage.text_block(reason, is_meta=True, meta_reason="Stop hook")
                        state.transcript.append(follow_up)
                        self.sessions.append(
                            "user_prompt",
                            {"agent": config.agent, "role": "user", "is_meta": True, "content": [block.to_api() for block in follow_up.content]},
                        )
                        continue
                    state.final_text = assistant.text
                    yield self._finish(state, "success")
                    return

                results: list[ToolResultBlock] = []
                halted: str | None = None
                for position, call in enumerate(calls):
                    if halted is not None:
                        # The run is stopping, but every tool_use in this assistant
                        # turn still needs a tool_result: a transcript with an
                        # orphaned tool_use cannot be sent to the API again, and a
                        # transcript that cannot be sent cannot be resumed or
                        # compacted. So the refusal is recorded, not swallowed.
                        results.append(
                            ToolResultBlock(
                                tool_use_id=call.id,
                                content=(
                                    f"not executed: this run halted after the current turn "
                                    f"because a ceiling was reached ({halted})"
                                ),
                                is_error=True,
                            )
                        )
                        continue
                    if config.max_tool_calls is not None and state.tool_calls >= config.max_tool_calls:
                        block, report = self._ceiling_refusal(call, state, turn_index)
                        results.append(block)
                        state.tool_reports.append(report)
                        halted = "error_max_tool_calls"
                        continue
                    block, report, fatal = self._dispatch(call, state, turn_index=turn_index, span=turn_span)
                    results.append(block)
                    state.tool_reports.append(report)
                    state.tool_calls += 1
                    if fatal is not None:
                        halted = fatal
                if not results:  # pragma: no cover - defensive: tool_use implies a result
                    results.append(ToolResultBlock(tool_use_id=calls[-1].id, content="no result produced", is_error=True))
                tool_message = UserMessage(content=tuple(results))
                state.transcript.append(tool_message)
                self._record_tool_message(tool_message)
                yield tool_message
                if halted is not None:
                    yield self._finish(state, halted)
                    return

        yield self._finish(state, "error_max_turns")

    # -- ceilings ----------------------------------------------------------
    def _ceiling_stop(self, state: _RunState) -> str | None:
        config = self.config
        if config.max_budget_usd is not None and self.budget.exhausted:
            return "error_max_budget_usd"
        if config.max_tool_calls is not None and state.tool_calls >= config.max_tool_calls:
            return "error_max_tool_calls"
        return None

    def _ceiling_refusal(self, call: ToolUseBlock, state: _RunState, turn_index: int) -> tuple[ToolResultBlock, ToolCallReport]:
        reason = f"the run reached its tool-call ceiling of {self.config.max_tool_calls}, so {call.name} was not executed"
        state.denials.append(Denial(tool=call.name, source="limit:max_tool_calls", reason=reason, agent=self.config.agent, turn_index=turn_index))
        block = ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True)
        report = ToolCallReport(
            name=call.name,
            call_id=call.id,
            is_error=True,
            denied=True,
            permission_source="limit:max_tool_calls",
            turn_index=turn_index,
            agent=self.config.agent,
        )
        return block, report

    # -- tool dispatch -----------------------------------------------------
    def _dispatch(
        self,
        call: ToolUseBlock,
        state: _RunState,
        *,
        turn_index: int,
        span: Any,
    ) -> tuple[ToolResultBlock, ToolCallReport, str | None]:
        """Run one call through hooks, then the gate, then the handler.

        Hook veto first so a hook can rewrite the input before policy looks at
        it; permission second so no hook ordering can bypass the gate. Returns a
        fatal result subtype when the caller must stop the run.
        """
        spec = self.tools.get(call.name)
        if spec is None:
            reason = (
                f"unknown tool {call.name!r}. Registered tools for this agent: "
                f"{', '.join(self.tools.names()) or '(none)'}."
            )
            if call.name == TASK_TOOL_NAME:
                # The name is absent because the policy took it away, so name the
                # knob that moved instead of leaving the model to guess.
                reason += (
                    f" Delegation is not available at depth {self.config.depth} "
                    f"(max_subagent_depth={self.config.max_subagent_depth}, "
                    f"allow_nested_delegation={self.config.allow_nested_delegation})."
                )
            self._fire(
                state,
                "PostToolUseFailure",
                HookInput(
                    event="PostToolUseFailure",
                    session_id=state.session_id,
                    agent=self.config.agent,
                    depth=self.config.depth,
                    turn_index=turn_index,
                    tool_name=call.name,
                    tool_use_id=call.id,
                    error=reason,
                ),
            )
            block = ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True)
            return block, ToolCallReport(name=call.name, call_id=call.id, is_error=True, permission_source="unknown_tool", turn_index=turn_index, agent=self.config.agent), None

        payload = dict(call.input) if isinstance(call.input, dict) else {}
        pre = self._fire(
            state,
            "PreToolUse",
            HookInput(
                event="PreToolUse",
                session_id=state.session_id,
                agent=self.config.agent,
                depth=self.config.depth,
                turn_index=turn_index,
                tool_name=spec.name,
                tool_use_id=call.id,
                tool_input=payload,
                data={"kind": spec.kind},
            ),
        )
        if pre.denied:
            self._trace_refusal(span, spec.name, source=f"hook:{pre.denied_by}", turn_index=turn_index)
            reason = f"{spec.name} refused by the {pre.denied_by} hook: {pre.deny_reason}"
            state.denials.append(Denial(tool=spec.name, source=f"hook:{pre.denied_by}", reason=reason, agent=self.config.agent, turn_index=turn_index))
            block = ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True)
            report = ToolCallReport(
                name=spec.name, call_id=call.id, is_error=True, denied=True, permission_source="hook", turn_index=turn_index, agent=self.config.agent
            )
            fatal = "error_permission_denied" if self.config.halt_on_denial else None
            return block, report, fatal
        if pre.updated_input is not None:
            payload = dict(pre.updated_input)
        rewritten = pre.updated_input is not None

        if spec.is_delegation:
            return self._delegate(call, spec, payload, state, turn_index=turn_index, span=span, rewritten=rewritten)

        decision = self.permissions.evaluate_spec(
            spec,
            payload,
            context=PermissionRequestContext(
                session_id=state.session_id,
                agent=self.config.agent,
                depth=self.config.depth,
                turn_index=turn_index,
                workspace=str(self.sandbox.root_real),
                mode=self.permissions.mode,
            ),
            known=True,
        )
        if not decision.allowed:
            self._trace_refusal(span, spec.name, source=decision.source, turn_index=turn_index)
            reason = f"{spec.name} refused by the permission gate: {decision.reason}"
            state.denials.append(
                Denial(tool=spec.name, source=decision.source, reason=reason, agent=self.config.agent, turn_index=turn_index)
            )
            self.sessions.append("denial", {"agent": self.config.agent, **Denial(tool=spec.name, source=decision.source, reason=reason, agent=self.config.agent, turn_index=turn_index).as_dict()})
            self._fire(
                state,
                "PostToolUseFailure",
                HookInput(
                    event="PostToolUseFailure",
                    session_id=state.session_id,
                    agent=self.config.agent,
                    depth=self.config.depth,
                    turn_index=turn_index,
                    tool_name=spec.name,
                    tool_use_id=call.id,
                    error=reason,
                    data={"denied": True, "source": decision.source},
                ),
            )
            block = ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True)
            report = ToolCallReport(
                name=spec.name,
                call_id=call.id,
                is_error=True,
                denied=True,
                permission_source=decision.source,
                turn_index=turn_index,
                agent=self.config.agent,
            )
            fatal = "error_permission_denied" if self.config.halt_on_denial else None
            return block, report, fatal

        context = ToolContext(
            session_id=state.session_id,
            agent=self.config.agent,
            depth=self.config.depth,
            turn_index=turn_index,
            sandbox=self.sandbox,
            limits=self.limits,
            services=self._services(),
        )
        started = time.monotonic()
        with span.child(f"tool:{spec.name}") as tool_span:
            tool_span.set_attributes(
                {
                    "tool.name": spec.name,
                    "tool.kind": spec.kind,
                    "tool.is_delegation": spec.is_delegation,
                    "tool.input_keys": sorted(str(key) for key in payload)[:32],
                    "permission.source": decision.source,
                    "turn.index": turn_index,
                    "hook.rewrote_input": rewritten,
                }
            )
            try:
                raw = spec.handler(payload, context)
            except (ToolAccessError, ToolInputError, ValueError, KeyError, TypeError, OSError) as error:
                result = ToolResult.error(f"{type(error).__name__}: {error}")
                tool_span.set_attribute("tool.error_class", type(error).__name__)
            except Exception as error:  # noqa: BLE001 - a broken tool must not kill the run
                result = ToolResult.error(f"tool {spec.name} failed: {type(error).__name__}")
                tool_span.set_attribute("tool.error_class", type(error).__name__)
            else:
                result = _coerce_result(raw, spec.name)
            duration_ms = int((time.monotonic() - started) * 1000)
            # Cost and outcome metadata only. The output body never reaches a span.
            tool_span.set_attributes(
                {
                    "tool.is_error": bool(result.is_error),
                    "tool.duration_ms": duration_ms,
                    "tool.result_chars": min(len(result.text()), 10_000_000),
                    "tool.truncated": bool(result.truncated),
                }
            )
        tool_text = result.text()
        if result.is_error:
            self._fire(
                state,
                "PostToolUseFailure",
                HookInput(
                    event="PostToolUseFailure",
                    session_id=state.session_id,
                    agent=self.config.agent,
                    depth=self.config.depth,
                    turn_index=turn_index,
                    tool_name=spec.name,
                    tool_use_id=call.id,
                    tool_input=payload,
                    tool_response=tool_text[:500],
                    tool_is_error=True,
                    error=tool_text[:500],
                    data={"duration_ms": duration_ms},
                ),
            )
        else:
            self._fire(
                state,
                "PostToolUse",
                HookInput(
                    event="PostToolUse",
                    session_id=state.session_id,
                    agent=self.config.agent,
                    depth=self.config.depth,
                    turn_index=turn_index,
                    tool_name=spec.name,
                    tool_use_id=call.id,
                    tool_input=payload,
                    tool_response=tool_text[:500],
                    data={"duration_ms": duration_ms, "truncated": bool(result.truncated)},
                ),
            )
        block = result.as_block(call.id, max_chars=self.limits.max_result_chars)
        report = ToolCallReport(
            name=spec.name,
            call_id=call.id,
            is_error=bool(result.is_error),
            permission_source=decision.source,
            duration_ms=duration_ms,
            result_chars=len(tool_text),
            truncated=bool(result.truncated),
            input_rewritten=rewritten,
            turn_index=turn_index,
            agent=self.config.agent,
        )
        return block, report, None

    def _trace_refusal(self, turn_span: Any, tool_name: str, *, source: str, turn_index: int) -> None:
        """A refusal is a governed outcome, so it belongs in the trace too."""
        with turn_span.child(f"tool:{tool_name}") as span:
            span.set_attributes(
                {
                    "tool.name": tool_name,
                    "tool.denied": True,
                    "tool.is_error": True,
                    "permission.source": source,
                    "turn.index": turn_index,
                }
            )

    def _services(self) -> dict[str, Any]:
        return {"registry": self.tools, "sidecar": self.sidecar, "config": self.config, "runtime": self}

    def _record_tool_message(self, message: UserMessage) -> None:
        """Write the tool_result turn, optionally without output bodies.

        ``record_tool_output_in_session=False`` is for hosts that want the audit
        trail (which tool, which agent, error or not) without persisting file
        contents it considers sensitive.
        """
        blocks: list[dict[str, Any]] = []
        for block in message.tool_results:
            text = block.text()
            if not self.config.record_tool_output_in_session and not block.is_error:
                text = f"[tool output omitted by configuration: {len(text)} chars]"
            blocks.append({"type": "tool_result", "tool_use_id": block.tool_use_id, "content": text, "is_error": block.is_error})
        self.sessions.append(
            "tool_result",
            {"agent": self.config.agent, "role": "user", "content": blocks, "is_meta": message.is_meta},
        )

    # -- delegation --------------------------------------------------------
    def _delegate(
        self,
        call: ToolUseBlock,
        spec: ToolSpec,
        payload: dict[str, Any],
        state: _RunState,
        *,
        turn_index: int,
        span: Any,
        rewritten: bool,
    ) -> tuple[ToolResultBlock, ToolCallReport, str | None]:
        """Gate and spawn a subagent as a child run.

        Permission is evaluated for each tool the *subagent declared*. Refusing the
        name ``Task`` would be wrong twice over: it would stop delegation from
        happening at all, and it would blame the delegation tool for a policy
        violation committed by the tool inside it.
        """
        agent_name = str(payload.get("agent") or self.config.default_subagent).strip()
        task_prompt = payload.get("prompt", payload.get("task", ""))
        definition = self.agents.get(agent_name)
        if definition is None:
            reason = (
                f"unknown subagent {agent_name!r}. Declared agents: {', '.join(self.agents.names()) or '(none)'}. "
                "The tool name Task is not the problem - the agent name is."
            )
            return (
                ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True),
                ToolCallReport(name=spec.name, call_id=call.id, is_error=True, permission_source="agent_registry", turn_index=turn_index, agent=self.config.agent),
                None,
            )
        if not isinstance(task_prompt, str) or not task_prompt.strip():
            return (
                ToolResultBlock(tool_use_id=call.id, content="Task input needs a non-empty 'prompt' string", is_error=True),
                ToolCallReport(name=spec.name, call_id=call.id, is_error=True, permission_source="input", turn_index=turn_index, agent=self.config.agent),
                None,
            )
        if not self._delegation_allowed(self.config.depth):
            reason = (
                f"delegation is not available at depth {self.config.depth} "
                f"(max_subagent_depth={self.config.max_subagent_depth}, "
                f"allow_nested_delegation={self.config.allow_nested_delegation})"
            )
            state.denials.append(Denial(tool=spec.name, source="policy:depth", reason=reason, agent=self.config.agent, turn_index=turn_index, kind="delegation"))
            return (
                ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True),
                ToolCallReport(name=spec.name, call_id=call.id, is_error=True, denied=True, permission_source="policy:depth", turn_index=turn_index, agent=self.config.agent),
                None,
            )

        missing = self.tools.missing([name for name in definition.tools if name != TASK_TOOL_NAME])
        if missing:
            reason = f"subagent {agent_name} declares tools this run cannot offer: {', '.join(missing)}"
            return (
                ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True),
                ToolCallReport(name=spec.name, call_id=call.id, is_error=True, permission_source="registry:subset", turn_index=turn_index, agent=self.config.agent),
                None,
            )

        gate = self.permissions.check_delegation(
            agent_name,
            definition.tools,
            kinds=self.tools.kinds(),
            context=PermissionRequestContext(
                session_id=state.session_id,
                agent=agent_name,
                depth=self.config.depth + 1,
                turn_index=turn_index,
                workspace=str(self.sandbox.root_real),
                mode=self.permissions.mode,
                reason_hint=f"{agent_name} subagent requests {len(definition.tools)} tools",
            ),
            disallowed_extra=tuple(set(self.config.disallowed_tools) | set(definition.disallowed_tools)),
        )
        if not gate.ok:
            reason = f"{definition.name} subagent was not permitted: {gate.summary}"
            for tool_name, why in gate.denied:
                state.denials.append(
                    Denial(tool=tool_name, source="delegation_gate", reason=why, agent=definition.name, turn_index=turn_index, kind="delegation")
                )
            self.sessions.append("denial", {"agent": self.config.agent, "tool": spec.name, "source": "delegation_gate", "reason": reason, "kind": "delegation", "turn_index": turn_index})
            return (
                ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True),
                ToolCallReport(name=spec.name, call_id=call.id, is_error=True, denied=True, permission_source="delegation_gate", turn_index=turn_index, agent=self.config.agent),
                "error_permission_denied" if self.config.halt_on_denial else None,
            )

        start = self._fire(
            state,
            "SubagentStart",
            HookInput(
                event="SubagentStart",
                session_id=state.session_id,
                agent=definition.name,
                depth=self.config.depth + 1,
                turn_index=turn_index,
                tool_name=spec.name,
                tool_use_id=call.id,
                tool_input=payload,
                prompt=task_prompt,
                data={"tools": list(gate.allowed), "permission_mode": definition.permission_mode},
            ),
        )
        if start.denied:
            reason = f"delegation to {definition.name} refused by the {start.denied_by} hook: {start.deny_reason}"
            state.denials.append(Denial(tool=spec.name, source=f"hook:{start.denied_by}", reason=reason, agent=definition.name, turn_index=turn_index, kind="delegation"))
            return (
                ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True),
                ToolCallReport(name=spec.name, call_id=call.id, is_error=True, denied=True, permission_source="hook:SubagentStart", turn_index=turn_index, agent=self.config.agent),
                "error_permission_denied" if self.config.halt_on_denial else None,
            )

        child_provider = self.provider
        if definition.provider:
            child_provider = self.providers.get(definition.provider)
            if child_provider is None:
                reason = (
                    f"subagent {definition.name} requests provider {definition.provider!r}, which this run was not "
                    f"given (available: {', '.join(sorted(self.providers)) or 'none'})"
                )
                return (
                    ToolResultBlock(tool_use_id=call.id, content=reason, is_error=True),
                    ToolCallReport(name=spec.name, call_id=call.id, is_error=True, permission_source="provider_registry", turn_index=turn_index, agent=self.config.agent),
                    None,
                )

        # Permission policy inheritance. The child must not be able to loosen what
        # the host decided for the run, and it must not silently *tighten* the parts
        # the host already auto-approved either: a parent whose policy allows Write
        # would otherwise get a subagent that refuses every call the gate just
        # approved, and the resulting error would blame a policy nobody set.
        #   - permission_mode: inherited, except an explicit ``plan`` definition,
        #     which is a hard "this agent must not change anything" rule.
        #   - allowed_tools: the parent's list, limited to what the agent declared.
        #   - disallowed_tools: the union, so a denial can never be undone.
        #   - can_use_tool: the host's callback stays attached, so every call the
        #     subagent makes still passes the same approval door.
        child_mode = "plan" if definition.permission_mode == "plan" else self.permissions.mode
        declared = tuple(name for name in definition.tools if name != TASK_TOOL_NAME)
        child_allowed = tuple(sorted(set(self.permissions.config.allowed_tools) & set(declared)))
        child_disallowed = tuple(
            sorted(set(self.config.disallowed_tools) | set(definition.disallowed_tools) | ({TASK_TOOL_NAME} if not self._child_may_delegate(definition) else set()))
        )

        child_budget_limit = definition.max_budget_usd
        remaining = self.budget.remaining()
        if remaining is not None:
            child_budget_limit = remaining if child_budget_limit is None else min(float(remaining), float(child_budget_limit))
        child_config = RuntimeConfig(
            model=definition.model or self.config.model,
            system_prompt=definition.system_prompt(parent_cwd=str(self.sandbox.root_real)),
            max_turns=definition.max_turns,
            max_tool_calls=definition.max_tool_calls,
            max_budget_usd=child_budget_limit,
            permission_mode=child_mode,
            allowed_tools=child_allowed,
            disallowed_tools=child_disallowed,
            workspace=str(self.sandbox.root_real),
            session_id=state.session_id,
            agent=definition.name,
            depth=self.config.depth + 1,
            allow_delegation=self._child_may_delegate(definition),
            max_subagent_depth=self.config.max_subagent_depth,
            allow_nested_delegation=self.config.allow_nested_delegation,
            halt_on_denial=self.config.halt_on_denial,
            max_output_tokens=self.config.max_output_tokens,
            compaction_threshold_tokens=definition.compaction_threshold_tokens if definition.compaction_threshold_tokens is not None else self.config.compaction_threshold_tokens,
            compaction_keep_messages=self.config.compaction_keep_messages,
            tool_limits=self.limits,
            sidecar_socket=self.config.sidecar_socket,
            sidecar_timeout_ms=self.config.sidecar_timeout_ms,
            include_describe_tool=False,
        )
        child = AgentRuntime(
            provider=child_provider,
            config=child_config,
            tools=self.tools.subset(definition.tools),
            permissions=PermissionEngine(
                PermissionConfig(
                    mode=child_mode,
                    allowed_tools=child_allowed,
                    disallowed_tools=child_disallowed,
                    can_use_tool=self.permissions.config.can_use_tool,
                )
            ),
            hooks=self.hooks,
            agents=self.agents,
            tracer=self.tracer,
            sessions=self.sessions,
            providers=self.providers,
            sidecar=self.sidecar,
            budget=Budget(max_budget_usd=child_config.max_budget_usd),
            summarizer=self.summarizer,
        )
        with span.child(f"subagent:{definition.name}") as sub_span:
            sub_span.set_attributes(
                {
                    "subagent.name": definition.name,
                    "subagent.depth": child_config.depth,
                    "subagent.permission_mode": child_mode,
                    "subagent.tools": list(definition.tools)[:32],
                    "subagent.provider": getattr(child_provider, "name", type(child_provider).__name__),
                }
            )
            events = tuple(child.run(task_prompt))
            report = child._last_report
            self.budget.observe_child(child.budget)
            verdict = parse_verdict(report.final_text, criteria=definition.acceptance_criteria, agent=definition.name) if definition.require_verdict else None
            subagent_report = SubagentReport(
                agent=definition.name,
                result=report.result,
                turns=report.result.num_turns if report.result else 0,
                tool_calls=len(report.tool_calls),
                cost_usd=child.budget.total_cost_usd,
                usage=child.budget.total_usage,
                verdict=verdict,
                final_text=report.final_text,
                denials=report.denials,
                transcript=render_transcript(report.transcript),
                permission_verdict=gate,
                depth=child_config.depth,
            )
            sub_span.set_attributes(
                {
                    "subagent.subtype": subagent_report.subtype,
                    "subagent.turns": subagent_report.turns,
                    "subagent.tool_calls": subagent_report.tool_calls,
                    "subagent.cost_usd": round(subagent_report.cost_usd, 10),
                    "subagent.usage_tokens": subagent_report.usage.total_tokens,
                    "subagent.denials": len(subagent_report.denials),
                }
            )
            if verdict is not None:
                sub_span.set_attributes({"subagent.acceptance": verdict.acceptance, "subagent.verdict_explicit": verdict.explicit})
        state.subagents.append(subagent_report)
        stop_verdict = self._fire(
            state,
            "SubagentStop",
            HookInput(
                event="SubagentStop",
                session_id=state.session_id,
                agent=definition.name,
                depth=self.config.depth + 1,
                turn_index=turn_index,
                tool_name=spec.name,
                tool_use_id=call.id,
                data={
                    "subtype": subagent_report.subtype,
                    "turns": subagent_report.turns,
                    "cost_usd": subagent_report.cost_usd,
                    "acceptance": verdict.acceptance if verdict else "",
                },
            ),
        )
        accepted = not stop_verdict.blocked
        self.sessions.append(
            "subagent",
            {"agent": self.config.agent, "child": definition.name, "host_accepted": accepted, **subagent_report.as_dict()},
        )

        body_parts = [
            f"[subagent {definition.name}] {subagent_report.subtype} in {subagent_report.turns} turn(s), "
            f"{subagent_report.tool_calls} tool call(s), ${subagent_report.cost_usd:.6f}"
        ]
        if subagent_report.final_text:
            body_parts.append(subagent_report.final_text)
        else:
            body_parts.append("(the subagent produced no final text)")
        if verdict is not None:
            body_parts.append(verdict.render())
        if not accepted:
            body_parts.append(
                f"[SubagentStop hook {stop_verdict.denied_by or 'policy'} refused to accept this result: "
                f"{stop_verdict.block_reason}]"
            )
        body = "\n".join(body_parts)
        result = ToolResult(
            content=body,
            is_error=subagent_report.subtype != "success" or not accepted,
            data={
                "agent": definition.name,
                "subtype": subagent_report.subtype,
                "cost_usd": subagent_report.cost_usd,
                "acceptance": verdict.acceptance if verdict else "",
            },
        )
        block = result.as_block(call.id, max_chars=self.limits.max_result_chars)
        report_row = ToolCallReport(
            name=spec.name,
            call_id=call.id,
            is_error=bool(result.is_error),
            permission_source="delegation_gate",
            result_chars=len(body),
            input_rewritten=rewritten,
            turn_index=turn_index,
            agent=self.config.agent,
        )
        return block, report_row, None

    def _child_may_delegate(self, definition: AgentDefinition) -> bool:
        if not definition.allow_delegation:
            return False
        if not self.config.allow_nested_delegation:
            return False
        return self._delegation_allowed(self.config.depth + 1)

    # -- compaction --------------------------------------------------------
    def _compact(self, state: _RunState, *, turn_index: int) -> CompactionOutcome:
        pre = self._fire(
            state,
            "PreCompact",
            HookInput(
                event="PreCompact",
                session_id=state.session_id,
                agent=self.config.agent,
                depth=self.config.depth,
                turn_index=turn_index,
                data={
                    "messages": len(state.transcript),
                    "tokens": estimate_transcript_tokens(state.transcript),
                    "threshold_tokens": self.config.compaction_threshold_tokens,
                },
            ),
        )
        if pre.denied:
            outcome = CompactionOutcome(
                performed=False,
                reason=f"compaction refused by the {pre.denied_by} hook: {pre.deny_reason}",
                transcript=tuple(state.transcript),
                tokens_before=estimate_transcript_tokens(state.transcript),
                tokens_after=estimate_transcript_tokens(state.transcript),
            )
            state.compactions.append(outcome.as_dict())
            return outcome
        instructions = "\n".join(pre.additional_context)
        outcome = compact(
            state.transcript,
            # The loop already applied the threshold to decide whether to compact
            # at all; force=True keeps the two checks from disagreeing.
            force=True,
            keep_messages=self.config.compaction_keep_messages,
            summarizer=self.summarizer,
            instructions=instructions,
        )
        state.compactions.append(outcome.as_dict())
        return outcome

    # -- shared helpers ----------------------------------------------------
    def _fire(self, state: _RunState, event: Any, payload: HookInput) -> Any:
        outcome = self.hooks.fire(event, payload)
        record: dict[str, Any] = {"event": event, **outcome.as_dict()}
        if payload.tool_name:
            record["tool"] = payload.tool_name
        state.hook_fires.append(record)
        if outcome.errors or outcome.ignored:
            self.sessions.append("hook", {"agent": self.config.agent, **record})
        return outcome

    def _result(self, state: _RunState, subtype: str) -> ResultMessage:
        duration_ms = int((time.monotonic() - state.started) * 1000)
        usage = self.budget.total_usage
        return ResultMessage(
            subtype=subtype,  # type: ignore[arg-type]
            num_turns=state.turns,
            duration_ms=duration_ms,
            total_cost_usd=self.budget.total_cost_usd,
            total_usage=usage,
            session_id=state.session_id,
            pricing_estimated=self.budget.pricing_estimated,
            errors=tuple(state.errors),
            permission_denials=tuple(denial.as_dict() for denial in state.denials),
            stop_reason=subtype,
        )

    def _finish(self, state: _RunState, subtype: str) -> ResultMessage:
        """Build the one ResultMessage and stash it for the report and the span."""
        result = self._result(state, subtype)
        state.result = result
        return result

    def _close_run(self, state: _RunState, run_span: Any) -> None:
        if not state.session_end_fired:
            state.session_end_fired = True
            subtype = state.result.subtype if state.result is not None else "error_during_execution"
            if state.result is not None and not self.config.depth:
                self.sessions.record_result(state.result)
            elif state.result is not None:
                self.sessions.append("result", {"subtype": subtype, "agent": self.config.agent, "inherited_by_parent": True})
            self._fire(
                state,
                "SessionEnd",
                HookInput(
                    event="SessionEnd",
                    session_id=state.session_id,
                    agent=self.config.agent,
                    depth=self.config.depth,
                    turn_index=state.turns,
                    data={"subtype": subtype, "total_cost_usd": self.budget.total_cost_usd},
                ),
            )
        # Everything the trace needs is written before the span closes, because a
        # post-end set_attribute is discarded in silence.
        run_span.set_attributes(
            {
                "result.subtype": state.result.subtype if state.result else "error_during_execution",
                "turn.count": state.turns,
                "tool.call_count": state.tool_calls,
                "cost.usd": round(self.budget.total_cost_usd, 10),
                "usage.total_tokens": self.budget.total_usage.total_tokens,
                "pricing.estimated": self.budget.pricing_estimated,
                "denial.count": len(state.denials),
                "compaction.count": len([item for item in state.compactions if item.get("performed")]),
                "stop.block_count": state.stop_blocks,
                "duration_ms": int((time.monotonic() - state.started) * 1000),
            }
        )
        usage_attrs = {f"usage.{key}": value for key, value in self.budget.total_usage.as_dict().items()}
        for key, value in usage_attrs.items():
            run_span.set_attribute(key, value)
        run_span.end()
        self._last_report = self._report(state.events, state=state)

    def _report(self, events: Sequence[Message], *, state: _RunState) -> RunReport:
        result = state.result
        if result is None and events:
            for event in events:
                if isinstance(event, ResultMessage):
                    result = event
        return RunReport(
            events=tuple(events),
            result=result,
            transcript=tuple(state.transcript),
            denials=tuple(state.denials),
            tool_calls=tuple(state.tool_reports),
            subagents=tuple(state.subagents),
            compactions=tuple(state.compactions),
            hook_fires=tuple(state.hook_fires),
            errors=tuple(state.errors),
            session_id=state.session_id,
            spans=tuple(self.tracer.names()),
            _trace=self.tracer.tree(),
        )

    # -- resume ------------------------------------------------------------
    def resume_transcript(self) -> list[Any]:
        return self.sessions.transcript()

    def continue_session(self, prompt: str) -> RunReport:
        return self.run_collect(prompt, resume=self.resume_transcript())

    def sidecar_probe(self) -> Any:
        if self.sidecar is None:
            raise RuntimeConfigurationError("no sidecar socket was configured for this run")
        return self.sidecar.probe()


def task_tool_spec() -> ToolSpec:
    """The delegation entry point. Read-only by classification, gated per tool."""
    return ToolSpec(
        name=TASK_TOOL_NAME,
        description=(
            "Delegate a self-contained task to a named subagent that runs with its own context, "
            "its own declared tool subset, and its own turn and budget ceilings. Provide a prompt "
            "that includes everything the subagent needs and the criteria for finishing. The subagent "
            "cannot see this conversation."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "agent": {"type": "string", "description": "Subagent name to delegate to"},
                "prompt": {"type": "string", "description": "The whole task, self-contained"},
            },
            "required": ["prompt"],
        },
        handler=_delegation_placeholder,
        kind="task",
        is_mutating=False,
        is_delegation=True,
        needs_workspace=False,
    )


def _delegation_placeholder(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    return ToolResult.error("the loop executes Task itself; a handler call here means dispatch is broken")


def _assign_tool_use_ids(blocks: Sequence[Any], state: _RunState) -> tuple[Any, ...]:
    """Give every tool_use an id, so results can be paired with calls.

    A provider that omits ``id`` would otherwise produce a transcript where two
    calls share an empty id, and the tool_result pairing - which is also what the
    compaction boundary check relies on - silently becomes ambiguous.
    """
    from providers.base import ToolUseBlock as _ToolUseBlock

    used = {call.id for call in state.transcript if isinstance(call, AssistantMessage) for call in call.tool_uses}
    filled: list[Any] = []
    for block in blocks:
        if isinstance(block, _ToolUseBlock) and not block.id:
            index = 0
            while True:
                index += 1
                candidate = f"toolu_{len(used) + index:04d}"
                if candidate not in used:
                    used.add(candidate)
                    block = replace(block, id=candidate)
                    break
        elif isinstance(block, _ToolUseBlock):
            used.add(block.id)
        filled.append(block)
    return tuple(filled)


def _coerce_result(raw: Any, tool_name: str) -> ToolResult:
    if isinstance(raw, ToolResult):
        return raw
    if isinstance(raw, bool):
        return ToolResult(content=f"{tool_name} returned {raw}")
    if isinstance(raw, (str, list, tuple, dict)):
        return ToolResult(content=raw)
    if raw is None:
        return ToolResult(content=f"{tool_name} returned no result")
    return ToolResult(content=str(raw))


def run_agent(
    prompt: str,
    *,
    provider: Any,
    config: RuntimeConfig | None = None,
    **kwargs: Any,
) -> RunReport:
    """One-shot convenience wrapper, mirroring ``query()`` in the SDK surface."""
    runtime = AgentRuntime(provider=provider, config=config, **kwargs)
    return runtime.run_collect(prompt)


__all__ = [
    "AgentRuntime",
    "DEFAULT_MODEL",
    "DEFAULT_SYSTEM_PROMPT",
    "Denial",
    "RunReport",
    "RuntimeConfig",
    "RuntimeConfigurationError",
    "SubagentReport",
    "TASK_TOOL_NAME",
    "ToolCallReport",
    "run_agent",
    "task_tool_spec",
]
