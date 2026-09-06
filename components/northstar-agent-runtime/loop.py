"""The governed agent loop: events, limits, hooks, permissions, subagents.

Division of labour: the runtime does reasoning and policy; execution that
needs the Codex CLI is delegated over a Unix socket to
``northstar-codex-sidecar`` (registered as the ``CodexReadOnly`` tool only
when a socket path is configured). The runtime never spawns a model CLI and
holds no model credentials.

Guarantees:

- A run emits ``SystemMessage(init)`` first and **exactly one**
  ``ResultMessage`` last. Every foreseeable failure is a ResultMessage with a
  dedicated subtype; the loop does not raise for them.
- Limits are independent: ``max_turns``, ``max_tool_calls``,
  ``max_budget_usd`` each have their own ResultMessage subtype.
- Compaction only ever cuts at a safe boundary (no orphaned tool_use).
- Tool handlers share one signature: ``handler(payload, ctx)``.
- A ``session_id`` exists even when no session store is configured.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Optional

from agents import AgentRegistry
from budget import BudgetTracker, Cost
from compaction import assert_valid_conversation, compact_messages, estimate_tokens
from hooks import HookRegistry
from permissions import PERMISSION_MODES, PermissionGate
from providers.base import (
    Provider,
    ProviderError,
    ProviderRequest,
    TextBlock,
    ToolUseBlock,
    assistant_wire_message,
    text_blocks,
    tool_use_blocks,
    user_text_message,
    user_tool_result_message,
)
from sessions import SessionStore
from sidecar_client import SidecarClient
from tools import ToolContext, ToolRegistry, ToolResult, builtin_tools
from tracing import RuntimeTracer

ResultSubtype = Literal[
    "success",
    "error_max_turns",
    "error_max_tool_calls",
    "error_max_budget_usd",
    "error_during_execution",
    "error_permission_denied",
]
RESULT_SUBTYPES = frozenset(
    ["success", "error_max_turns", "error_max_tool_calls", "error_max_budget_usd", "error_during_execution", "error_permission_denied"]
)
SystemSubtype = Literal["init", "compact_boundary", "informational"]
SYSTEM_SUBTYPES = frozenset(["init", "compact_boundary", "informational"])

DEFAULT_MODEL = "claude-sonnet-4-5"


# --- Events -------------------------------------------------------------------


def _base_to_dict(kind: str, session_id: str, run_id: str, extra: dict[str, Any]) -> dict[str, Any]:
    return {"type": kind, "session_id": session_id, "run_id": run_id, **extra}


@dataclass
class SystemMessage:
    subtype: str
    data: dict[str, Any]
    session_id: str = ""
    run_id: str = ""

    def __post_init__(self) -> None:
        if self.subtype not in SYSTEM_SUBTYPES:
            raise ValueError(f"invalid SystemMessage subtype: {self.subtype!r}")

    def to_dict(self) -> dict[str, Any]:
        return _base_to_dict("system", self.session_id, self.run_id, {"subtype": self.subtype, "data": self.data})


@dataclass
class AssistantMessage:
    text: str
    tool_uses: list[dict[str, Any]]
    session_id: str = ""
    run_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _base_to_dict("assistant", self.session_id, self.run_id, {"text": self.text, "tool_uses": self.tool_uses})


@dataclass
class UserMessage:
    text: str
    session_id: str = ""
    run_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _base_to_dict("user", self.session_id, self.run_id, {"text": self.text})


@dataclass
class ResultMessage:
    subtype: str
    summary: str
    num_turns: int = 0
    num_tool_calls: int = 0
    total_cost_usd: float = 0.0
    usage: dict[str, int] = field(default_factory=dict)
    pricing_estimated: bool = False
    session_id: str = ""
    run_id: str = ""

    def __post_init__(self) -> None:
        if self.subtype not in RESULT_SUBTYPES:
            raise ValueError(f"invalid ResultMessage subtype: {self.subtype!r}")

    def to_dict(self) -> dict[str, Any]:
        return _base_to_dict(
            "result",
            self.session_id,
            self.run_id,
            {
                "subtype": self.subtype,
                "summary": self.summary,
                "num_turns": self.num_turns,
                "num_tool_calls": self.num_tool_calls,
                "total_cost_usd": self.total_cost_usd,
                "usage": self.usage,
                "pricing_estimated": self.pricing_estimated,
            },
        )


Event = SystemMessage | AssistantMessage | UserMessage | ResultMessage  # type: ignore[valid-type]


# --- Configuration -------------------------------------------------------------


@dataclass
class RunConfig:
    model: str = DEFAULT_MODEL
    system: str = ""
    workspace: Path = field(default_factory=lambda: Path.cwd())
    max_turns: int = 50
    max_tool_calls: int = 100
    max_budget_usd: Optional[float] = None
    permission_mode: str = "default"
    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()
    can_use_tool: Optional[Callable[[str, dict[str, Any], str], Any]] = None
    subagents: AgentRegistry = field(default_factory=AgentRegistry)
    max_subagent_depth: int = 1
    hooks: HookRegistry = field(default_factory=HookRegistry)
    compaction_threshold_tokens: Optional[int] = None
    compaction_keep_messages: int = 6
    sidecar_socket: Optional[str] = None
    session_path: Optional[Path] = None
    # Internal: restrict the tool registry to a named subset (subagents).
    tool_names: Optional[tuple[str, ...]] = None


@dataclass
class RunReport:
    events: list[Event]
    result: ResultMessage
    session_id: str
    run_id: str


@dataclass
class _Internal:
    depth: int = 0
    parent_session_id: Optional[str] = None
    root_budget: Optional[BudgetTracker] = None  # shared whole-run tracker
    root_budget_usd: Optional[float] = None  # whole-run cap
    seed_session_id: Optional[str] = None  # explicit session id (subagents)
    tracer: Optional["RuntimeTracer"] = None  # inherited so subagent spans stay in one tree


# --- Runtime -------------------------------------------------------------------


class AgentRuntime:
    def __init__(self, provider: Provider, config: Optional[RunConfig] = None, _internal: Optional[_Internal] = None) -> None:
        self.provider = provider
        self.config = config or RunConfig()
        if self.config.permission_mode not in PERMISSION_MODES:
            raise ValueError(f"unknown permission_mode: {self.config.permission_mode!r}")
        self._internal = _internal or _Internal()
        self._depth = self._internal.depth

        # Workspace is the sandbox root: resolve it once (symlinks included).
        self.workspace = Path(self.config.workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

        # Whole-run budget: the main agent owns the root tracker; subagents
        # share it so their spend counts toward the parent cap.
        if self._internal.root_budget is not None:
            self.budget = BudgetTracker()
            self.root_budget = self._internal.root_budget
            self._root_budget_usd = self._internal.root_budget_usd
        else:
            self.budget = BudgetTracker()
            self.root_budget = self.budget
            self._root_budget_usd = self.config.max_budget_usd

        self._sidecar_client = SidecarClient(self.config.sidecar_socket) if self.config.sidecar_socket else None
        self._tool_registry = self._build_tool_registry()
        self._gate = PermissionGate(
            allowed_tools=self.config.allowed_tools,
            disallowed_tools=self.config.disallowed_tools,
            permission_mode=self.config.permission_mode,
            can_use_tool=self.config.can_use_tool,
            tool_kinds=self._tool_registry.kinds(),
            subagents=self.config.subagents,
            depth=self._depth,
            max_subagent_depth=self.config.max_subagent_depth,
        )
        # Subagents inherit the parent's tracer so the whole span tree lands
        # in one TracerProvider.
        self.tracer = self._internal.tracer if self._internal.tracer is not None else RuntimeTracer()
        self._session_id = ""

    def _build_tool_registry(self) -> ToolRegistry:
        tools = builtin_tools(
            include_codex=self._sidecar_client is not None,
            include_task=bool(self.config.subagents),
        )
        if self.config.tool_names is not None:
            allowed = set(self.config.tool_names)
            tools = [t for t in tools if t.name in allowed]
        return ToolRegistry(tools)

    # -- helpers ----------------------------------------------------------------

    def _record_usage(self, model: str, usage: Any) -> Cost:
        cost = self.budget.record(model, usage)
        if self.root_budget is not self.budget:
            self.root_budget.record(model, usage)
        return cost

    def _budget_exhausted(self) -> bool:
        if self.config.max_budget_usd is not None and self.budget.total_usd >= self.config.max_budget_usd:
            return True
        if self._root_budget_usd is not None and self.root_budget.total_usd >= self._root_budget_usd:
            return True
        return False

    def _budget_summary(self) -> str:
        cap = self.config.max_budget_usd if self.config.max_budget_usd is not None else self._root_budget_usd
        return f"total cost ${self.root_budget.total_usd:.6f}, cap ${cap}"

    # -- the run -----------------------------------------------------------------

    def run(self, prompt: str) -> RunReport:
        run_id = uuid.uuid4().hex
        if not isinstance(prompt, str) or not prompt.strip():
            # Still a well-formed report, not an exception.
            session_id = self._internal.seed_session_id or uuid.uuid4().hex
            result = ResultMessage(
                subtype="error_during_execution",
                summary="prompt must be a non-empty string",
                session_id=session_id,
                run_id=run_id,
            )
            return RunReport(events=[result], result=result, session_id=session_id, run_id=run_id)

        seed = self._internal.seed_session_id
        store: Optional[SessionStore] = None
        if self.config.session_path is not None:
            store = SessionStore(self.config.session_path, session_id=seed)
        session_id = store.session_id if store is not None else (seed or uuid.uuid4().hex)
        self._session_id = session_id

        events: list[Event] = []

        def emit(event: Event) -> None:
            events.append(event)
            if store is not None:
                store.append({"ts": time.time(), "run_id": run_id, "event": event.to_dict()})

        turns = 0
        tool_calls = 0

        def finish(subtype: str, summary: str) -> RunReport:
            result = ResultMessage(
                subtype=subtype,
                summary=summary,
                num_turns=turns,
                num_tool_calls=tool_calls,
                total_cost_usd=self.budget.total_usd,
                usage=self.budget.usage.to_dict(),
                pricing_estimated=self.budget.pricing_estimated,
                session_id=session_id,
                run_id=run_id,
            )
            emit(result)
            return RunReport(events=events, result=result, session_id=session_id, run_id=run_id)

        emit(
            SystemMessage(
                "init",
                {
                    "model": self.config.model,
                    "session_id": session_id,
                    "parent_session_id": self._internal.parent_session_id,
                    "depth": self._depth,
                    "tools": list(self._tool_registry.names()),
                    "permission_mode": self.config.permission_mode,
                    "max_turns": self.config.max_turns,
                    "max_tool_calls": self.config.max_tool_calls,
                    "max_budget_usd": self.config.max_budget_usd,
                },
                session_id,
                run_id,
            )
        )
        self.config.hooks.fire(
            "SessionStart", {"session_id": session_id, "run_id": run_id, "prompt": prompt, "depth": self._depth}
        )

        try:
            with self.tracer.span(
                "run",
                {
                    "agent.model": self.config.model,
                    "agent.session_id": session_id,
                    "agent.depth": self._depth,
                    "agent.permission_mode": self.config.permission_mode,
                },
            ) as run_span:
                decision = self.config.hooks.fire(
                    "UserPromptSubmit",
                    {"prompt": prompt, "session_id": session_id, "run_id": run_id, "depth": self._depth},
                )
                if not decision.allowed:
                    run_span.set_attribute("agent.result", "error_permission_denied")
                    return finish(
                        "error_permission_denied",
                        f"run rejected by UserPromptSubmit hook: {decision.reason or 'no reason given'}",
                    )

                effective_prompt = prompt
                if decision.additional_context:
                    effective_prompt = (
                        f"{prompt}\n\n<user-context>\n{decision.additional_context}\n</user-context>"
                    )
                    emit(
                        SystemMessage(
                            "informational",
                            {"note": "UserPromptSubmit hook injected additional context"},
                            session_id,
                            run_id,
                        )
                    )
                emit(UserMessage(effective_prompt, session_id, run_id))

                messages = [user_text_message(effective_prompt)]
                tool_schemas = tuple(self._tool_registry.schemas())

                while True:
                    turns += 1
                    if turns > self.config.max_turns:
                        # Report the turns actually executed, not the one that
                        # tripped the limit.
                        turns -= 1
                        run_span.set_attribute("agent.result", "error_max_turns")
                        return finish(
                            "error_max_turns",
                            f"stopped: max_turns={self.config.max_turns} reached after {turns} turns",
                        )
                    if self._budget_exhausted():
                        run_span.set_attribute("agent.result", "error_max_budget_usd")
                        return finish("error_max_budget_usd", f"stopped: budget exhausted ({self._budget_summary()})")

                    with self.tracer.span(f"turn[{turns}]", {"turn.index": turns}) as turn_span:
                        # -- one model generation --
                        with self.tracer.span("generation", {"gen.model": self.config.model}) as gen_span:
                            request = ProviderRequest(
                                model=self.config.model,
                                messages=tuple(messages),
                                system=self.config.system,
                                tools=tool_schemas,
                            )
                            try:
                                response = self.provider.create_message(request)
                            except ProviderError as exc:
                                gen_span.set_attribute("gen.error", True)
                                run_span.set_attribute("agent.result", "error_during_execution")
                                return finish("error_during_execution", f"provider error: {exc}")
                            except Exception as exc:  # unexpected: still an event, not a raise
                                gen_span.set_attribute("gen.error", True)
                                run_span.set_attribute("agent.result", "error_during_execution")
                                return finish(f"error_during_execution", f"provider error: {type(exc).__name__}")

                            cost = self._record_usage(self.config.model, response.usage)
                            # Usage/cost attributes are set BEFORE the span ends:
                            # the OTel SDK silently drops set_attribute after end().
                            gen_span.set_attribute("gen.input_tokens", response.usage.input_tokens)
                            gen_span.set_attribute("gen.output_tokens", response.usage.output_tokens)
                            gen_span.set_attribute("gen.cache_read_input_tokens", response.usage.cache_read_input_tokens)
                            gen_span.set_attribute("gen.cache_creation_input_tokens", response.usage.cache_creation_input_tokens)
                            gen_span.set_attribute("gen.cost_usd", cost.usd)
                            gen_span.set_attribute("gen.pricing_estimated", cost.pricing_estimated)

                        if self._budget_exhausted():
                            # Stop before executing this generation's tool calls:
                            # a spent budget must not buy more side effects.
                            run_span.set_attribute("agent.result", "error_max_budget_usd")
                            return finish(
                                "error_max_budget_usd",
                                f"stopped: budget exhausted ({self._budget_summary()}); "
                                "pending tool calls were not executed",
                            )

                        assistant_text = "".join(b.text for b in text_blocks(response.content))
                        blocks = tool_use_blocks(response.content)
                        emit(
                            AssistantMessage(
                                assistant_text,
                                [{"id": b.id, "name": b.name, "input": dict(b.input)} for b in blocks],
                                session_id,
                                run_id,
                            )
                        )
                        messages.append(assistant_wire_message(response.content))

                        if not blocks:
                            stop_decision = self.config.hooks.fire(
                                "Stop", {"turns": turns, "text": assistant_text, "depth": self._depth}
                            )
                            if not stop_decision.allowed:
                                reason = stop_decision.reason or "stop blocked by hook"
                                emit(
                                    SystemMessage(
                                        "informational",
                                        {"note": "Stop hook refused to end the run; feeding reason back as a new user turn", "reason": reason},
                                        session_id,
                                        run_id,
                                    )
                                )
                                messages.append(user_text_message(reason))
                                continue
                            run_span.set_attribute("agent.result", "success")
                            return finish("success", assistant_text or "run complete")

                        # -- execute this turn's tool calls --
                        for block in blocks:
                            tool_calls += 1
                            if tool_calls > self.config.max_tool_calls:
                                run_span.set_attribute("agent.result", "error_max_tool_calls")
                                return finish(
                                    "error_max_tool_calls",
                                    f"stopped: max_tool_calls={self.config.max_tool_calls} reached",
                                )
                            result = self._execute_tool(block, session_id, run_id, emit)
                            messages.append(
                                user_tool_result_message(
                                    [
                                        {
                                            "tool_use_id": block.id,
                                            "content": result.output,
                                            "is_error": bool(result.is_error),
                                        }
                                    ]
                                )
                            )

                        # -- compaction: only here, at a safe boundary --
                        if self.config.compaction_threshold_tokens is not None and (
                            estimate_tokens(messages) >= self.config.compaction_threshold_tokens
                        ):
                            pre = self.config.hooks.fire(
                                "PreCompact", {"session_id": session_id, "turns": turns, "depth": self._depth}
                            )
                            if pre.allowed and not pre.skip:
                                new_messages, dropped = compact_messages(messages, self.config.compaction_keep_messages)
                                if dropped:
                                    try:
                                        # Defensive: compaction must never produce a
                                        # conversation the API would reject.
                                        assert_valid_conversation(new_messages)
                                    except ValueError as exc:
                                        run_span.set_attribute("agent.result", "error_during_execution")
                                        return finish("error_during_execution", f"compaction invariant violated: {exc}")
                                    messages = new_messages
                                    emit(
                                        SystemMessage(
                                            "compact_boundary",
                                            {
                                                "dropped_messages": dropped,
                                                "kept_messages": len(new_messages),
                                            },
                                            session_id,
                                            run_id,
                                        )
                                    )
        finally:
            last = events[-1] if events else None
            self.config.hooks.fire(
                "SessionEnd",
                {
                    "session_id": session_id,
                    "run_id": run_id,
                    "result_subtype": getattr(last, "subtype", None),
                },
            )

    # -- tool execution ------------------------------------------------------------

    def _execute_tool(self, block: ToolUseBlock, session_id: str, run_id: str, emit: Callable[[Event], None]) -> ToolResult:
        tool = self._tool_registry.get(block.name)
        if tool is None:
            return ToolResult(f"unknown tool: {block.name}", is_error=True)

        payload = dict(block.input)

        pre = self.config.hooks.fire(
            "PreToolUse",
            {
                "tool_name": block.name,
                "input": payload,
                "tool_use_id": block.id,
                "depth": self._depth,
                "session_id": session_id,
            },
        )
        if pre.updated_input is not None:
            payload = dict(pre.updated_input)
        if not pre.allowed:
            reason = pre.reason or "denied by PreToolUse hook"
            emit(
                SystemMessage("informational", {"note": f"tool '{block.name}' denied", "reason": reason}, session_id, run_id)
            )
            return ToolResult(f"permission denied: {reason}", is_error=True)

        decision = self._gate.check_tool(block.name, tool.kind, payload)
        if not decision.allowed:
            emit(
                SystemMessage(
                    "informational",
                    {"note": f"tool '{block.name}' denied by permissions", "reason": decision.reason},
                    session_id,
                    run_id,
                )
            )
            return ToolResult(f"permission denied: {decision.reason}", is_error=True)

        ctx = ToolContext(
            workspace=self.workspace,
            session_id=session_id,
            depth=self._depth,
            model=self.config.model,
            subagents=self.config.subagents,
            sidecar=self._sidecar_client,
            spawn_subagent=self._spawn_subagent,
        )
        with self.tracer.span(f"tool:{block.name}", {"tool.name": block.name, "tool.kind": tool.kind}) as span:
            try:
                result = tool.handler(payload, ctx)
            except Exception as exc:  # a crashing handler is a tool failure, not a run failure
                result = ToolResult(f"tool '{block.name}' failed: {type(exc).__name__}: {exc}", is_error=True)
            span.set_attribute("tool.is_error", bool(result.is_error))

        if result.is_error:
            after = self.config.hooks.fire(
                "PostToolUseFailure",
                {"tool_name": block.name, "input": payload, "output": result.output, "depth": self._depth},
            )
            if not after.allowed:
                result = ToolResult(
                    f"{result.output}\n[PostToolUseFailure hook: {after.reason or 'denied'}]", is_error=True
                )
        else:
            after = self.config.hooks.fire(
                "PostToolUse",
                {"tool_name": block.name, "input": payload, "output": result.output, "depth": self._depth},
            )
            if not after.allowed:
                # A PostToolUse deny converts a successful result into a failure;
                # terminal, like every other deny.
                result = ToolResult(f"denied by PostToolUse hook: {after.reason or 'no reason given'}", is_error=True)
        return result

    # -- subagents -------------------------------------------------------------------

    def _spawn_subagent(self, agent_name: str, prompt: str) -> ToolResult:
        definition = self.config.subagents.get(agent_name)
        if definition is None:
            return ToolResult(f"unknown agent: {agent_name}", is_error=True)

        start = self.config.hooks.fire(
            "SubagentStart", {"agent": agent_name, "prompt": prompt, "depth": self._depth + 1}
        )
        if not start.allowed:
            return ToolResult(f"subagent '{agent_name}' denied by SubagentStart hook: {start.reason or 'no reason given'}", is_error=True)

        child_config = RunConfig(
            model=definition.model or self.config.model,
            system=definition.system,
            workspace=self.workspace,
            max_turns=definition.max_turns,
            max_tool_calls=self.config.max_tool_calls,
            max_budget_usd=definition.max_budget_usd,
            permission_mode=self.config.permission_mode,
            allowed_tools=self.config.allowed_tools,
            disallowed_tools=self.config.disallowed_tools,
            can_use_tool=self.config.can_use_tool,
            subagents=self.config.subagents,
            max_subagent_depth=self.config.max_subagent_depth,
            hooks=self.config.hooks,
            compaction_threshold_tokens=None,  # subagents stay un-compacted
            sidecar_socket=self.config.sidecar_socket,
            session_path=self.config.session_path,
            tool_names=definition.tools,
        )
        child = AgentRuntime(
            definition.provider or self.provider,
            child_config,
            _internal=_Internal(
                depth=self._depth + 1,
                parent_session_id=self._session_id,
                root_budget=self.root_budget,
                root_budget_usd=self._root_budget_usd,
                seed_session_id=uuid.uuid4().hex,
                tracer=self.tracer,
            ),
        )
        # subagent:Type span (child of the enclosing tool:Task span) wraps the
        # subagent's own run/turn tree. Cost is recorded before the span ends.
        with self.tracer.span(
            f"subagent:{agent_name}",
            {"subagent.type": agent_name, "subagent.depth": self._depth + 1},
        ) as sub_span:
            report = child.run(prompt)
            sub_span.set_attribute("subagent.result", report.result.subtype)
            sub_span.set_attribute("subagent.turns", report.result.num_turns)
            sub_span.set_attribute("subagent.tool_calls", report.result.num_tool_calls)
            sub_span.set_attribute("subagent.cost_usd", report.result.total_cost_usd)
        self.config.hooks.fire(
            "SubagentStop",
            {
                "agent": agent_name,
                "depth": self._depth + 1,
                "subtype": report.result.subtype,
                "summary": report.result.summary,
            },
        )
        meta = {
            "subagent": agent_name,
            "subagent_session_id": report.session_id,
            "subagent_result_subtype": report.result.subtype,
            "subagent_cost_usd": report.result.total_cost_usd,
        }
        if report.result.subtype == "success":
            return ToolResult(report.result.summary, meta=meta)
        return ToolResult(
            f"subagent '{agent_name}' ended with {report.result.subtype}: {report.result.summary}",
            is_error=True,
            meta=meta,
        )
