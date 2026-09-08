"""Python API for one governed Northstar run — embed the loop, don't shell out.

This is the programmatic face of the runtime, kept deliberately thin over the
same machinery the CLI drives: build the registry, apply the permission
settings, run the loop, and hand back plain dicts.

Minimal usage (offline, deterministic — no API key):

.. code-block:: python

    import sdk

    report = sdk.run(prompt="Summarise notes.txt", workspace="examples/demo/workspace")
    print(report.subtype, report.exit_code, report.session_id)

Everything the CLI governs is available here: permission modes, allow/deny
lists, read-only, turn/tool/budget ceilings, halt-on-denial, a session
directory for the append-only transcript, subagent depth and workspace agent
files. Two entry points share one configuration:

* :func:`run` — run to completion, return a :class:`RunReport` with the full
  event list (``report.events`` are the same dicts ``--json`` emits);
* :func:`stream_run` — yield those dicts as they happen; the final dict is the
  ``result`` event (see :mod:`events` for the shape and ``EXIT_CODES``).

Deep configuration (policy files, AGENTS.md/context files, skills, MCP
servers, agent-definition runs) is intentionally left to the CLI: those
features are repository-level opinions, while this API is the stable
embedding contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence

from events import EXIT_CODES, event_to_dict

DEFAULT_MODEL = "claude-sonnet-4-5"
_READ_ONLY_KINDS = ("edit", "write")


@dataclass
class RunOptions:
    """Everything :func:`run` / :func:`stream_run` need to start one run.

    Defaults mirror the CLI: ``scripted`` provider (offline, deterministic),
    ``default`` permission mode (mutating tools denied until allowed), no
    session directory (transcript not persisted).
    """

    prompt: str = ""
    workspace: str = "."
    provider: str | Any = "scripted"  # "scripted" | "anthropic" | a providers.base.Provider
    model: str = DEFAULT_MODEL
    system_prompt: str | None = None
    scripted_turns: Sequence[Any] | None = None  # scripted provider turns; None -> one text reply
    permission_mode: str = "default"
    allowed_tools: Sequence[str] = ()
    disallowed_tools: Sequence[str] = ()
    read_only: bool = False
    max_turns: int = 25
    max_tool_calls: int | None = 50
    max_budget_usd: float | None = None
    halt_on_denial: bool = False
    session_dir: str | None = None  # persist the append-only JSONL transcript here
    max_subagent_depth: int = 1
    allow_nested_delegation: bool = False
    compaction_threshold_tokens: int | None = 60_000  # None disables compaction
    max_output_tokens: int = 4096
    redact_tool_output: bool = False  # omit tool output bodies from the transcript
    stream: bool = False  # yield stream_delta events while assistant text is produced (transcript unchanged)
    lock_session: bool = True  # claim the session transcript before appending to it; contention ends the run as error_session_busy (exit 7), writing nothing
    session_lease_seconds: int = 900  # how long the claim promises liveness, renewed while the run lives; a live holder is never displaced
    workspace_agents: bool = True  # register .northstar/agents/*.md definitions
    checkpoint_turns: int = 0  # append a resumable boundary record every N turns (0 = off)
    resume_from: str | None = None  # session id to fork from its latest checkpoint; the parent file is never written


@dataclass
class RunReport:
    """Outcome of one completed run: structured summary + full event list."""

    subtype: str
    session_id: str
    num_turns: int
    duration_ms: int
    total_cost_usd: float
    total_usage: dict[str, Any]
    pricing_estimated: bool
    tool_calls: int
    errors: list[str]
    permission_denials: list[dict[str, Any]]
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_error(self) -> bool:
        return self.subtype != "success"

    @property
    def exit_code(self) -> int:
        """Terminal exit code a wrapper should use (``events.EXIT_CODES``)."""
        return EXIT_CODES.get(self.subtype, 1)

    @property
    def result_event(self) -> dict[str, Any]:
        """The trailing ``result`` dict of :attr:`events`."""
        return self.events[-1] if self.events else {}


# -- construction -----------------------------------------------------------


def _build_provider(options: RunOptions) -> Any:
    if isinstance(options.provider, str):
        if options.provider == "scripted":
            from providers.scripted import ScriptedProvider

            turns = options.scripted_turns
            if turns is None:
                turns = [{"text": "(scripted reply: no turns configured; pass scripted_turns)"}]
            return ScriptedProvider(list(turns), model=options.model)
        if options.provider == "anthropic":
            try:
                from providers.anthropic import AnthropicProvider
            except ImportError as error:  # pragma: no cover - depends on extras
                raise ValueError(
                    "the 'anthropic' provider needs the optional dependency; "
                    "pip install northstar-agent-runtime[anthropic]"
                ) from error
            return AnthropicProvider(model=options.model, max_tokens=options.max_output_tokens)
        raise ValueError(f"unknown provider {options.provider!r} (use 'scripted', 'anthropic' or a Provider instance)")
    return options.provider


def _apply_read_only(registry: Any, disallowed: list[str]) -> list[str]:
    """read_only refuses every default-registry tool whose kind is edit/write."""
    names = [spec.name for spec in registry.specs() if spec.kind in _READ_ONLY_KINDS]
    return list(dict.fromkeys([*disallowed, *names]))


def _build(options: RunOptions, resume: str | None = None) -> tuple[Any, Any, list[Any]]:
    """Assemble (runtime, session store) from options; raises ValueError on bad input.

    ``resume`` reopens the persisted session under its own id (the transcript is
    appended to the same file), matching the CLI's ``--resume`` semantics.
    """
    from agent_files import register_workspace_agents
    from agents import builtin_registry
    from loop import AgentRuntime, RuntimeConfig
    from permissions import subtract
    from sessions import SessionStore
    from tools import ToolLimits, build_default_registry

    if not options.prompt.strip():
        raise ValueError("prompt must be non-empty text")

    registry = build_default_registry()
    denied = _apply_read_only(registry, list(options.disallowed_tools)) if options.read_only else list(options.disallowed_tools)
    allowed = subtract(list(options.allowed_tools), denied)
    denied = tuple(dict.fromkeys(denied))

    agents = builtin_registry()
    if options.workspace_agents and options.workspace:
        register_workspace_agents(agents, options.workspace, known_tools=registry.names())

    config_kwargs: dict[str, Any] = {
        "model": options.model,
        "max_turns": options.max_turns,
        "max_tool_calls": options.max_tool_calls,
        "max_budget_usd": options.max_budget_usd,
        "permission_mode": options.permission_mode,
        "allowed_tools": allowed,
        "disallowed_tools": denied,
        "workspace": options.workspace,
        "max_output_tokens": options.max_output_tokens,
        "compaction_threshold_tokens": options.compaction_threshold_tokens,
        "max_subagent_depth": options.max_subagent_depth,
        "allow_nested_delegation": options.allow_nested_delegation,
        "halt_on_denial": options.halt_on_denial,
        "tool_limits": ToolLimits(),
        "record_tool_output_in_session": not options.redact_tool_output,
        "stream": options.stream,
    }
    if options.system_prompt is not None:
        config_kwargs["system_prompt"] = options.system_prompt
    provider = _build_provider(options)

    # A checkpoint resume forks: new session id, new file, counters and cost carried
    # over from the parent, and the parent transcript never opened for writing.
    resume_transcript: list[Any] = []
    budget: Any = None
    if options.resume_from:
        from budget import Budget
        from checkpoints import CheckpointError, select as select_checkpoint
        from providers.base import Usage

        if not options.session_dir:
            raise ValueError("resume_from needs session_dir to read the parent transcript from")
        try:
            from loop import AgentRuntime as _AR, RuntimeConfigurationError as _RCE  # noqa: F401 - parity of the raised type

            parent_store = SessionStore(options.session_dir, session_id=options.resume_from)
            records, _dropped = parent_store.read(options.resume_from)
            checkpoint = select_checkpoint(records)
        except (CheckpointError, OSError, ValueError) as error:
            raise ValueError(f"cannot resume from {options.resume_from!r}: {error}") from error
        if checkpoint is None:
            raise ValueError(
                f"session {options.resume_from!r} has no checkpoints: run it with checkpoint_turns=N first"
            )
        config_kwargs["resume_from"] = checkpoint
        config_kwargs["parent_session"] = options.resume_from
        config_kwargs["max_turns"] = max(int(options.max_turns), checkpoint.turns)
        data = checkpoint.usage
        budget = Budget(
            max_budget_usd=options.max_budget_usd,
            total_cost_usd=checkpoint.cost_usd,
            total_usage=Usage(
                input_tokens=int(data.get("input_tokens", 0) or 0),
                output_tokens=int(data.get("output_tokens", 0) or 0),
                cache_read_input_tokens=int(data.get("cache_read_input_tokens", 0) or 0),
                cache_creation_input_tokens=int(data.get("cache_creation_input_tokens", 0) or 0),
            ),
        )
        store = SessionStore(options.session_dir or None, session_id=None)
        resume_transcript = store.transcript(options.resume_from)
    else:
        store = SessionStore(options.session_dir or None, session_id=resume or None)
        if resume:
            resume_transcript = store.transcript(resume)
    if options.checkpoint_turns:
        config_kwargs["checkpoint_turns"] = options.checkpoint_turns
    config_kwargs["lock_session"] = options.lock_session
    config_kwargs["session_lease_seconds"] = options.session_lease_seconds
    config_kwargs["session_id"] = store.session_id
    runtime = AgentRuntime(
        provider=provider,
        config=RuntimeConfig(**config_kwargs),
        tools=registry,
        sessions=store,
        agents=agents,
        budget=budget,
    )
    return runtime, store, resume_transcript


def _events(runtime: Any, prompt: str, resume: Sequence[Any] | None = None) -> Iterator[dict[str, Any]]:
    for event in runtime.run(prompt, resume=resume):
        yield event_to_dict(event)


def stream_run(options: RunOptions, resume: str | None = None) -> Iterator[dict[str, Any]]:
    """Run one governed loop, yielding each event as a plain dict.

    The final dict is the ``result`` event (``subtype``/``errors``/
    ``permission_denials``/``session_id`` ...). Pass ``resume`` with the id of
    a persisted session (``options.session_dir`` must be set) to continue from
    its transcript.

    With ``options.stream`` the assistant text also arrives as ``stream_delta`` dicts
    before the matching ``assistant`` event, and ``"".join(delta)`` equals that event's
    text (or is a prefix of it, once the runtime's per-turn cap has been reached). The
    loop still ends at exactly one ``result``, and ``run()`` reports the same numbers
    whether or not anything was streamed.
    """
    runtime, _store, resume_transcript = _build(options, resume=resume)
    yield from _events(runtime, options.prompt, resume_transcript)


def run(options: RunOptions, resume: str | None = None) -> RunReport:
    """Run one governed loop to completion and return its :class:`RunReport`.

    ``resume`` continues a persisted session (see :func:`stream_run`).
    """
    runtime, store, resume_transcript = _build(options, resume=resume)
    events: list[dict[str, Any]] = []
    result: dict[str, Any] | None = None
    for event_dict in _events(runtime, options.prompt, resume_transcript):
        events.append(event_dict)
        if event_dict.get("type") == "result":
            result = event_dict
    report = runtime.last_report
    return RunReport(
        subtype=str(result.get("subtype", "")) if result else "",
        session_id=str(result.get("session_id", "")) if result else "",
        num_turns=int(result.get("num_turns", 0)) if result else 0,
        duration_ms=int(result.get("duration_ms", 0)) if result else 0,
        total_cost_usd=float(result.get("total_cost_usd", 0.0)) if result else 0.0,
        total_usage=dict(result.get("total_usage", {})) if result else {},
        pricing_estimated=bool(result.get("pricing_estimated", False)) if result else False,
        tool_calls=len(report.tool_calls) if report is not None else 0,
        errors=list(result.get("errors", [])) if result else [],
        permission_denials=list(result.get("permission_denials", [])) if result else [],
        events=events,
    )
