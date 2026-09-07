"""Command-line entry point for one governed run.

The CLI is a thin shell around :class:`~loop.AgentRuntime`: it builds a
:class:`~loop.RuntimeConfig`, wires the provider, and streams the event sequence.
Every interesting failure - an exhausted script, a denied tool, a budget stop -
still arrives as a ``ResultMessage`` and becomes an exit code, so the shell can
tell the outcomes apart:

=====  ==============================================
0      success
1      error_during_execution
2      error_max_turns
3      error_max_tool_calls
4      error_max_budget_usd
5       error_permission_denied
64     usage or configuration error (nothing was run)
=====  ==============================================

Offline use, which is how the tests exercise it:

    python3 -m cli run --provider scripted --script demo.json --prompt "hi" \\
        --workspace /tmp/ws --deny-tool Write

``--deny-tool`` subtracts from the computed allow list instead of leaving a name
in both lists, because a name in both lists is an operator mistake the engine
would otherwise report as a policy conflict rather than doing what was asked.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from _version import __version__
from doctor import add_arguments as add_doctor_arguments
from doctor import run_doctor
from providers.base import ResultMessage
from session_view import add_arguments as add_session_arguments

EXIT_CODES = {
    "success": 0,
    "error_during_execution": 1,
    "error_max_turns": 2,
    "error_max_tool_calls": 3,
    "error_max_budget_usd": 4,
    "error_permission_denied": 5,
}
USAGE_ERROR = 64

#: Tools that change state; ``--read-only`` refuses them at the gate.
MUTATING_TOOLS = ("Write", "Edit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="northstar-agent-runtime",
        description="Run one governed Northstar agent loop.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 -m cli run --provider scripted --script plan.json --prompt 'summarise README'\n"
            "  python3 -m cli run --workspace . --read-only --sidecar-socket /var/run/northstar-codex/sidecar.sock\n"
            "  python3 -m cli tools --workspace .\n"
            "  python3 -m cli doctor --workspace .\n"
            "  python3 -m cli sessions list --session-dir /tmp/northstar-sessions\n"
            "  python3 -m cli sessions show --session-dir /tmp/northstar-sessions ns-20260907T000000Z-00000000\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"northstar-agent-runtime {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run one agent loop to completion")
    _add_run_arguments(run)

    sub.add_parser("tools", help="list the built-in tools and their classification")
    agents = sub.add_parser("agents", help="list the built-in subagent definitions")
    agents.add_argument("--workspace", default=".", help="workspace used to describe tool availability")
    doctor = sub.add_parser("doctor", help="self-check the host for one governed run (no requests, no file writes)")
    add_doctor_arguments(doctor)
    sessions = sub.add_parser("sessions", help="inspect persisted session transcripts (read-only)")
    add_session_arguments(sessions)
    return parser


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    prompt = parser.add_argument_group("prompt")
    prompt.add_argument("--prompt", default="", help="the task text")
    prompt.add_argument("--prompt-file", default="", help="read the task from a file, or '-' for stdin")

    provider = parser.add_argument_group("provider")
    provider.add_argument("--provider", choices=("scripted", "anthropic"), default="scripted", help="model provider (default: scripted, offline)")
    provider.add_argument("--model", default="claude-sonnet-4-5", help="model id used for pricing and requests")
    provider.add_argument("--script", default="", help="JSON file of scripted turns (scripted provider only)")
    provider.add_argument("--scripted-text", default="", help="single scripted answer; shorthand for a one-turn script")
    provider.add_argument("--max-output-tokens", type=int, default=4096, help="generation cap")
    provider.add_argument("--system-prompt", default="", help="override the runtime system prompt")

    limits = parser.add_argument_group("limits")
    limits.add_argument("--max-turns", type=int, default=25, help="turn ceiling (error_max_turns)")
    limits.add_argument("--max-tool-calls", type=int, default=50, help="tool-call ceiling (error_max_tool_calls)")
    limits.add_argument("--max-budget-usd", type=float, default=None, help="cost ceiling in USD (error_max_budget_usd)")
    limits.add_argument("--compaction-threshold-tokens", type=int, default=60_000, help="compact above this many estimated tokens; 0 disables")
    limits.add_argument("--compaction-keep-messages", type=int, default=4, help="tail size never summarised")

    policy = parser.add_argument_group("policy")
    policy.add_argument("--workspace", default=".", help="directory the tools are confined to")
    policy.add_argument("--permission-mode", choices=("default", "acceptEdits", "plan", "bypassPermissions"), default="default")
    policy.add_argument("--allow-tool", action="append", default=[], metavar="NAME", help="auto-approve a tool (repeatable)")
    policy.add_argument("--deny-tool", action="append", default=[], metavar="NAME", help="always refuse a tool, and remove it from the allow list (repeatable)")
    policy.add_argument("--read-only", action="store_true", help="deny Write and Edit")
    policy.add_argument("--plan", action="store_true", help="shorthand for --permission-mode plan")
    policy.add_argument("--agent", default="", help="run as a built-in subagent definition (its tools and ceilings apply)")
    policy.add_argument("--max-subagent-depth", type=int, default=1, help="0 disables delegation")
    policy.add_argument("--allow-nested-delegation", action="store_true", help="subagents may delegate one level deeper")
    policy.add_argument("--halt-on-denial", action="store_true", help="end the run with error_permission_denied when a call is refused")
    policy.add_argument("--no-policy-file", action="store_true", help="ignore .northstar/config.toml in the workspace")
    context_group = policy.add_mutually_exclusive_group()
    context_group.add_argument("--context-file", default="", metavar="PATH", help="inject this project-instructions file into the system prompt (must live inside the workspace)")
    context_group.add_argument("--no-project-context", action="store_true", help="do not auto-inject AGENTS.md (or the policy file's project_context)")

    execution = parser.add_argument_group("execution delegation")
    execution.add_argument("--sidecar-socket", default="", help="Unix socket of northstar-codex-sidecar; enables the CodexReadOnly tool")
    execution.add_argument("--sidecar-timeout-ms", type=int, default=30_000, help="sidecar execution deadline")
    execution.add_argument("--probe-sidecar", action="store_true", help="send one health-check prompt to the sidecar and exit")

    output = parser.add_argument_group("output")
    output.add_argument("--json", action="store_true", help="emit every event as a JSONL line")
    output.add_argument("--quiet", action="store_true", help="print only the final result line")
    output.add_argument("--trace", action="store_true", help="print the span tree afterwards")
    output.add_argument("--session-dir", default="", help="append an auditable JSONL transcript here")
    output.add_argument("--resume", default="", help="session id to continue from --session-dir")
    output.add_argument("--redact-tool-output", action="store_true", help="record tool results in the session without output bodies")
    output.add_argument("--show-pricing", action="store_true", help="print the pricing decision and exit")
    output.add_argument("--dry-run", action="store_true", help="validate the configuration and print what a run would do, then exit without sending any request (provider, model, and sidecar are not touched)")


def _load_script(path: str) -> list[Any]:
    text = Path(path).read_text(encoding="utf-8")
    value = json.loads(text)
    if isinstance(value, dict) and "turns" in value:
        value = value["turns"]
    if not isinstance(value, list):
        raise ValueError("a script must be a JSON array of turns, or an object with a 'turns' array")
    return value


def _tool_lists(args: argparse.Namespace, *, base_tools: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve allow/deny lists, subtracting denies (never co-listing them)."""
    from permissions import subtract

    denied = list(args.deny_tool)
    if args.read_only:
        denied.extend(MUTATING_TOOLS)
    allowed = list(args.allow_tool)
    if not allowed and args.permission_mode == "bypassPermissions":
        allowed = list(base_tools)
    return subtract(allowed, denied), tuple(dict.fromkeys(denied))


def _build_provider(args: argparse.Namespace) -> Any:
    if args.provider == "scripted":
        from providers.scripted import ScriptedProvider

        if args.script and args.scripted_text:
            raise ValueError("--script and --scripted-text are mutually exclusive")
        if args.script:
            return ScriptedProvider(_load_script(args.script), model=args.model)
        text = args.scripted_text or "(no scripted reply configured; pass --script or --scripted-text)"
        return ScriptedProvider([{"text": text}], model=args.model)
    if args.provider == "anthropic":
        from providers.anthropic import AnthropicProvider

        return AnthropicProvider(model=args.model, max_tokens=args.max_output_tokens)
    raise ValueError(f"unknown provider {args.provider!r}")


def _check_anthropic_sdk() -> tuple[bool, str]:
    """Whether the ``anthropic`` package is importable, and how to fix it if not.

    Imported on demand (never at module import time) so the rest of the CLI stays
    usable on hosts that only run the offline scripted provider.
    """
    if importlib.util.find_spec("anthropic") is not None:
        return True, "anthropic SDK is installed"
    return False, "the 'anthropic' package is not installed; pip install -r requirements.txt, or use --provider scripted"


def _print_dry_run(args: argparse.Namespace, runtime: Any, *, policy_note: str = "none", context_note: str = "off") -> int:
    """Print what a run would do and exit, without constructing a provider.

    ``--dry-run`` is the read-only twin of ``--show-pricing``: it validates the
    configuration the same way a real run would (including the workspace policy
    file, if any), but never builds a provider and never touches the network,
    the model SDK, or the sidecar socket.
    """
    from budget import price_for

    config = runtime.config
    pricing, estimated = price_for(config.model)
    tool_names = runtime.tools.names()

    agent_suffix = "" if config.agent in ("", "main") else f" (agent '{config.agent}')"
    print(f"provider={args.provider} model={config.model}{agent_suffix}")
    print(f"permission_mode={config.permission_mode}")
    print(f"tools={','.join(tool_names) or '(none)'}")
    print(f"allowed_tools={','.join(config.allowed_tools) or '(none)'}  "
          f"disallowed_tools={','.join(config.disallowed_tools) or '(none)'}")
    print(f"max_turns={config.max_turns} "
          f"max_tool_calls={config.max_tool_calls or 'unlimited'} "
          f"max_budget_usd={config.max_budget_usd or 'unlimited'}")
    print(f"sidecar={'on' if config.sidecar_socket else 'off'} "
          f"session_dir={args.session_dir or 'off'} "
          f"halt_on_denial={config.halt_on_denial}")
    print(f"policy_file={policy_note}")
    print(f"project_context={context_note}")
    print(f"pricing: ${pricing.input_per_mtok}/MTok in, ${pricing.output_per_mtok}/MTok out "
          f"(cache read x0.1, cache write x1.25)"
          + (" - estimated" if estimated else ""))
    print(f"estimated cost: ~${pricing.input_per_mtok / 1000:.3f} per 100K input tokens, "
          f"~${pricing.output_per_mtok / 1000:.3f} per 100K output tokens")
    print("dry-run: configuration is valid; no request was sent")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "tools":
        from tools import build_default_registry

        for spec in build_default_registry().specs():
            print(f"{spec.name:<14} {spec.kind:<8} {'mutating' if spec.is_mutating else 'read-only':<10} {spec.description[:60]}")
        return 0
    if args.command == "agents":
        from agents import builtin_registry

        for definition in builtin_registry():
            print(f"{definition.name:<12} tools={','.join(definition.tools)}")
            print(f"{'':<12} mode={definition.permission_mode} turns={definition.max_turns} verdict={definition.require_verdict}")
            print(f"{'':<12} {definition.description}")
        return 0
    if args.command != "run":
        if args.command == "doctor":
            return run_doctor(args)
        if args.command == "sessions":
            from session_view import run_sessions

            return run_sessions(args)
        parser.print_help()
        return USAGE_ERROR

    try:
        return _run(args)
    except ValueError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return USAGE_ERROR
    except FileNotFoundError as error:
        print(f"file not found: {error}", file=sys.stderr)
        return USAGE_ERROR
    except OSError as error:  # pragma: no cover - host-level failure
        print(f"cannot run: {error}", file=sys.stderr)
        return USAGE_ERROR


def _run(args: argparse.Namespace) -> int:
    from agents import builtin_registry
    from loop import AgentRuntime, DEFAULT_SYSTEM_PROMPT, RuntimeConfig, RuntimeConfigurationError
    from permissions import validate_mode
    from policy_file import PolicyFileError, append_project_context, discover_project_context, load_policy_file
    from sessions import SessionStore
    from tools import ToolLimits, build_default_registry

    prompt = args.prompt
    if args.prompt_file:
        if args.prompt_file == "-":
            prompt = sys.stdin.read()
        else:
            prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    if args.probe_sidecar and not prompt.strip():
        prompt = "Reply with OK"
    if not prompt.strip():
        print("no prompt: pass --prompt, --prompt-file, or --probe-sidecar", file=sys.stderr)
        return USAGE_ERROR

    registry = build_default_registry()
    agents = builtin_registry()

    # Workspace policy file (.northstar/config.toml). It may only tighten; any
    # violation is a configuration error (exit 64), never a silent ignore.
    policy = None
    if not args.no_policy_file:
        try:
            policy = load_policy_file(args.workspace, known_tools=registry.names(), known_agents=agents.names())
        except PolicyFileError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR

    cli_mode = "plan" if args.plan else args.permission_mode
    validate_mode(cli_mode)
    # The file may pin 'plan' (or keep 'default'); it may never loosen. A CLI
    # mode other than the built-in default is an explicit operator choice and
    # wins. --no-policy-file is the escape hatch for an explicit 'default'.
    mode = (
        policy.permission_mode
        if (policy is not None and policy.permission_mode is not None and cli_mode == "default")
        else cli_mode
    )
    validate_mode(mode)

    allowed_cli, denied_cli = _tool_lists(args, base_tools=registry.names())
    denied_list = list(denied_cli)
    if policy is not None:
        # File denials and read_only are a floor: they add to the CLI denials
        # and the permission gate's first layer keeps them terminal.
        denied_list.extend(policy.deny_tools)
        if policy.read_only:
            denied_list.extend(MUTATING_TOOLS)
    denied = tuple(dict.fromkeys(denied_list))
    allowed = tuple(name for name in allowed_cli if name not in denied)

    definition = None
    agent_name = args.agent or (policy.agent if policy is not None else "")
    if agent_name:
        definition = agents.get(agent_name)
        if definition is None:
            # A typo (in a flag or in the policy file) is a usage error, not a traceback.
            raise ValueError(f"unknown agent {agent_name!r}. Known agents: {', '.join(agents.names()) or '(none)'}")
        # Running *as* a built-in definition inherits its tool subset and ceilings;
        # the host's and policy file's deny lists still apply on top.
        registry = registry.subset(definition.tools)
        allowed = tuple(name for name in allowed if name in registry.names())

    def tighten(cli_value: int | None, file_value: int | None) -> int | None:
        """Policy-file ceilings may only lower; when both are set, the lower wins."""
        candidates = [value for value in (cli_value, file_value) if value is not None]
        return min(candidates) if candidates else None

    base_turns = definition.max_turns if definition else args.max_turns
    base_tool_calls = definition.max_tool_calls if definition else args.max_tool_calls
    max_turns = tighten(base_turns, policy.max_turns if policy is not None else None)
    max_tool_calls = tighten(base_tool_calls, policy.max_tool_calls if policy is not None else None)
    max_budget_usd = tighten(args.max_budget_usd, policy.max_budget_usd if policy is not None else None)
    compaction_threshold = tighten(
        args.compaction_threshold_tokens,
        policy.compaction_threshold_tokens if policy is not None else None,
    )
    halt_on_denial = bool(args.halt_on_denial or (policy is not None and policy.halt_on_denial))

    config_kwargs: dict[str, Any] = {
        "model": (definition.model if definition and definition.model else args.model),
        "max_turns": max_turns,
        "max_tool_calls": max_tool_calls,
        "max_budget_usd": max_budget_usd,
        "permission_mode": definition.permission_mode if definition else mode,
        "allowed_tools": allowed,
        "disallowed_tools": denied,
        "workspace": args.workspace,
        "max_output_tokens": args.max_output_tokens,
        "compaction_threshold_tokens": compaction_threshold or None,
        "compaction_keep_messages": args.compaction_keep_messages,
        "max_subagent_depth": args.max_subagent_depth,
        "allow_nested_delegation": args.allow_nested_delegation,
        "halt_on_denial": halt_on_denial,
        "tool_limits": ToolLimits(),
        "record_tool_output_in_session": not args.redact_tool_output,
    }
    if args.system_prompt:
        config_kwargs["system_prompt"] = args.system_prompt
    if definition:
        config_kwargs["system_prompt"] = definition.system_prompt(parent_cwd=args.workspace)
        config_kwargs["agent"] = definition.name
        config_kwargs["allow_delegation"] = definition.allow_delegation and args.max_subagent_depth > 0

    # Project instructions (AGENTS.md by default, the policy file's
    # project_context, or an explicit --context-file) are appended to whichever
    # system prompt applies, as clearly delimited developer-authored content.
    context = None
    if args.context_file or not args.no_project_context:
        configured = policy.project_context_setting if policy is not None else "AGENTS.md"
        context = discover_project_context(
            args.workspace,
            configured=configured,
            explicit=args.context_file or None,
        )
        if context is not None:
            base_prompt = config_kwargs.get("system_prompt", DEFAULT_SYSTEM_PROMPT)
            config_kwargs["system_prompt"] = append_project_context(base_prompt, context)
    if args.sidecar_socket:
        config_kwargs["sidecar_socket"] = args.sidecar_socket
        config_kwargs["sidecar_timeout_ms"] = args.sidecar_timeout_ms

    store = SessionStore(args.session_dir or None, session_id=args.resume or None)
    config_kwargs["session_id"] = store.session_id
    try:
        config = RuntimeConfig(**config_kwargs)
    except RuntimeConfigurationError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return USAGE_ERROR

    if args.no_policy_file:
        policy_note = "none (--no-policy-file)"
    elif policy is not None:
        policy_note = (
            f"{policy.source} mode={policy.permission_mode or 'default'} "
            f"deny={','.join(policy.deny_tools) or 'none'} "
            f"read_only={bool(policy.read_only)} budget={policy.max_budget_usd or 'none'} "
            f"max_turns={policy.max_turns or 'none'} halt_on_denial={bool(policy.halt_on_denial)}"
        )
    else:
        policy_note = "none"
    if context is not None:
        context_note = f"{context.name} ({len(context.text)} chars from {context.path})" + (" [truncated]" if context.truncated else "")
    elif args.no_project_context and not args.context_file:
        context_note = "off (--no-project-context)"
    else:
        context_note = "off (no AGENTS.md in the workspace)"

    provider = _build_provider(args)
    runtime = AgentRuntime(provider=provider, config=config, tools=registry, sessions=store, agents=agents)

    if args.show_pricing:
        print(json.dumps(runtime.pricing(), indent=2, sort_keys=True))
        return 0
    if args.dry_run:
        # Never constructs the provider: configuration is validated above, so a
        # healthy configuration prints a plan and exits 0 before any request.
        return _print_dry_run(args, runtime, policy_note=policy_note, context_note=context_note)
    if args.probe_sidecar:
        if args.provider == "anthropic":
            sdk_ok, message = _check_anthropic_sdk()
            if not sdk_ok:
                print(message, file=sys.stderr)
                return USAGE_ERROR
        if runtime.sidecar is None:
            print("--probe-sidecar needs --sidecar-socket", file=sys.stderr)
            return USAGE_ERROR
        probe = runtime.sidecar.probe()
        print(json.dumps(probe.as_dict(), indent=2, sort_keys=True))
        return 0 if probe.ok else 1

    resume = store.transcript(args.resume) if args.resume else None
    exit_code = 0
    result = None
    for event in runtime.run(prompt, resume=resume):
        if args.json:
            print(json.dumps(_event_to_json(event), ensure_ascii=False, sort_keys=True))
        else:
            _print_event(event, quiet=args.quiet)
        if isinstance(event, ResultMessage):
            result = event
            exit_code = EXIT_CODES.get(event.subtype, 1)
    if args.trace:
        print(runtime.tracer.tree())
    # --quiet suppresses the narration, not the result: a script wrapping the CLI
    # still gets exactly one line to parse, including the session id.
    if result is not None and not args.json:
        report = runtime.last_report
        tool_calls = len(report.tool_calls) if report is not None else 0
        print(
            f"\n[{result.subtype}] turns={result.num_turns} tool_calls={tool_calls} "
            f"cost=${result.total_cost_usd:.6f}"
            + (" (pricing estimated)" if result.pricing_estimated else "")
            + f" session={result.session_id}"
        )
        # A run that ended in error must say why; the summary line alone is a dead
        # end for whoever is reading a CI log.
        for message in result.errors:
            print(f"  ! {message}", file=sys.stderr)
        for denial in result.permission_denials:
            name = denial.get("tool", "?") if isinstance(denial, dict) else getattr(denial, "tool", "?")
            print(f"  ! refused: {name}", file=sys.stderr)
    return exit_code


def _event_to_json(event: Any) -> dict[str, Any]:
    kind = type(event).__name__
    if kind == "ResultMessage":
        return {
            "type": "result",
            "subtype": event.subtype,
            "is_error": event.is_error,
            "num_turns": event.num_turns,
            "duration_ms": event.duration_ms,
            "total_cost_usd": event.total_cost_usd,
            "total_usage": event.total_usage.as_dict(),
            "session_id": event.session_id,
            "pricing_estimated": event.pricing_estimated,
            "errors": list(event.errors),
            "permission_denials": list(event.permission_denials),
        }
    if kind == "SystemMessage":
        return {"type": "system", "subtype": event.subtype, "content": event.content, "data": event.data}
    if kind == "AssistantMessage":
        return {
            "type": "assistant",
            "content": [block.to_api() for block in event.content],
            "model": event.model,
            "usage": event.usage.as_dict(),
            "stop_reason": event.stop_reason,
        }
    if kind == "UserMessage":
        return {"type": "user", "content": [block.to_api() for block in event.content], "is_meta": event.is_meta}
    return {"type": kind.lower(), "repr": str(event)[:400]}


def _print_event(event: Any, *, quiet: bool = False) -> None:
    kind = type(event).__name__
    if quiet and kind != "ResultMessage":
        return
    if kind == "SystemMessage":
        if event.subtype == "init":
            print(f"· session {event.data.get('session_id')} provider={event.data.get('provider')} model={event.data.get('model')}")
            print(f"· tools {', '.join(event.data.get('tools', ()))}")
            print(f"· permission_mode={event.data.get('permission_mode')} sidecar={'on' if event.data.get('sidecar') else 'off'}")
        elif event.subtype == "compact_boundary":
            print(f"· compacted {event.data.get('dropped_messages')} message(s): {event.data.get('tokens_before')} -> {event.data.get('tokens_after')} est. tokens")
        elif event.content:
            print(f"· {event.content}")
        return
    if kind == "AssistantMessage":
        for block in event.content:
            name = type(block).__name__
            if name == "TextBlock" and block.text:
                print(block.text)
            elif name == "ToolUseBlock":
                print(f"→ {block.name} {json.dumps(block.input, ensure_ascii=False, sort_keys=True)[:160]}")
        return
    if kind == "UserMessage":
        for block in event.content:
            if type(block).__name__ == "ToolResultBlock":
                marker = "error" if block.is_error else "ok"
                text = " ".join(block.text().split())
                print(f"← {marker}: {text[:160]}" + ("..." if len(text) > 160 else ""))
        return
    if kind == "ResultMessage":
        return


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess in tests
    raise SystemExit(main())
