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
5      error_permission_denied
6      error_postconditions_failed (a --verify / [[verify]] check did not hold)
7      error_session_busy (another live run holds the session transcript)
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
from events import EXIT_CODES, event_to_dict
from doctor import add_arguments as add_doctor_arguments
from doctor import run_doctor
from providers.base import ResultMessage
from session_view import add_arguments as add_session_arguments
from plugin_load import add_plugin_arguments
from mcp_config import add_mcp_arguments
from skill_check import add_skills_arguments

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
            "  python3 -m cli new my-project  # scaffold a governed project\n"
            "  python3 -m cli sessions show --session-dir /tmp/northstar-sessions ns-20260907T000000Z-00000000\n"
            "  python3 -m cli plugin install ./my-bundle --workspace . && python3 -m cli plugin verify --workspace .\n"
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
    mcp = sub.add_parser(
        "mcp",
        help="inspect the MCP servers this workspace declares (read-only; a run needs --mcp-config to start them)",
    )
    add_mcp_arguments(mcp)
    skills = sub.add_parser("skills", help="review the workspace's Agent Skills (supply-chain check, read-only)")
    add_skills_arguments(skills)
    plugins = sub.add_parser(
        "plugin",
        help="install, verify and export plugin bundles (a pinned set of skills/agents/hooks/MCP servers)",
    )
    add_plugin_arguments(plugins)
    new_proj = sub.add_parser("new", help="scaffold a governed project (config, agents, hooks guide, CI recipe)")
    new_proj.add_argument("directory", help="directory to create (must not exist, or be empty unless --force)")
    new_proj.add_argument("--force", action="store_true", help="write the template files into a non-empty directory (never deletes)")
    return parser


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    prompt = parser.add_argument_group("prompt")
    prompt.add_argument("--prompt", default="", help="the task text")
    prompt.add_argument("--prompt-file", default="", help="read the task from a file, or '-' for stdin")

    provider = parser.add_argument_group("provider")
    provider.add_argument(
        "--provider",
        choices=("scripted", "anthropic", "openai"),
        default="scripted",
        help="model provider (default: scripted, offline); 'openai' speaks the Chat Completions wire, so it covers OpenAI, Azure, vLLM, SGLang, Ollama, LiteLLM, OpenRouter and similar gateways",
    )
    provider.add_argument(
        "--model",
        default="",
        help="model id used for pricing and requests (default per provider: claude-sonnet-4-5, or gpt-4.1 for --provider openai)",
    )
    provider.add_argument(
        "--base-url",
        default="",
        metavar="URL",
        help="OpenAI-compatible endpoint base URL (default: $OPENAI_BASE_URL; the key is read from $OPENAI_API_KEY and is never taken from a flag)",
    )
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

    transport = parser.add_argument_group("provider transport")
    transport.add_argument(
        "--retry-max-attempts",
        type=int,
        default=None,
        metavar="N",
        help=(
            "provider requests allowed per turn (1 = none). A workspace [retry] table caps this: "
            "the flag may ask for fewer, never more"
        ),
    )
    transport.add_argument(
        "--retry-deadline-ms",
        type=int,
        default=None,
        metavar="MS",
        help="how long one turn may spend waiting between requests (request time itself is the provider's timeout)",
    )
    transport.add_argument(
        "--retry-on",
        default=None,
        metavar="CLASSES",
        help=(
            "comma-separated fault classes to retry: rate_limited, overloaded, network, timeout, "
            "server_error (anything else is refused: an auth or bad-request fault is not made true by repetition)"
        ),
    )
    transport.add_argument(
        "--no-retry",
        action="store_true",
        help="report the first provider fault immediately - what a CI job that must not stall wants",
    )

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
    policy.add_argument(
        "--require-skill-lock",
        action="store_true",
        help="refuse to start unless every installed skill matches the digest recorded by `skills check --write-lock`",
    )
    policy.add_argument(
        "--checkpoint-turns",
        type=int,
        default=0,
        metavar="N",
        help="append a resumable checkpoint every N turn boundaries (0 = off); a resumed run inherits the consumed turns, tool calls and cost",
    )
    policy.add_argument(
        "--verify",
        action="append",
        default=[],
        metavar="KIND:PATH[:TEXT]",
        help="postcondition checked independently of the model after the run: exists, absent, changed, unchanged "
        "or contains; a failed check ends the run with error_postconditions_failed",
    )
    policy.add_argument("--no-policy-file", action="store_true", help="ignore .northstar/config.toml in the workspace")
    policy.add_argument("--no-workspace-agents", action="store_true", help="ignore .northstar/agents/*.md subagent files")
    policy.add_argument("--no-skills", action="store_true", help="do not list .northstar/skills/*/SKILL.md packages in the system prompt")
    policy.add_argument(
        "--no-plugins",
        action="store_true",
        help="ignore .northstar/plugins/ entirely (installed bundles contribute skills, agents, hooks, MCP servers and ceilings)",
    )
    policy.add_argument(
        "--enable-workspace-hooks",
        action="store_true",
        help="run the [[hooks]] declared in .northstar/config.toml (default off: cloning a repository must not mean executing it)",
    )
    policy.add_argument(
        "--allow-policy-writes",
        action="store_true",
        help="let mutating tools write under .northstar (default: refused - the agent must not rewrite its own governance)",
    )
    policy.add_argument(
        "--run-id",
        default="",
        metavar="ID",
        help="correlation id for this run; also used as the sidecar request_id (default: generated)",
    )
    context_group = policy.add_mutually_exclusive_group()
    context_group.add_argument("--context-file", default="", metavar="PATH", help="inject this project-instructions file into the system prompt (must live inside the workspace)")
    context_group.add_argument("--no-project-context", action="store_true", help="do not auto-inject AGENTS.md (or the policy file's project_context)")

    mcp = parser.add_argument_group("mcp servers (experimental)")
    mcp.add_argument(
        "--mcp-config",
        default="off",
        metavar="auto|PATH|off",
        help=(
            "also start the servers this workspace declares in its own MCP config file "
            "(.mcp.json, .cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json). Off by "
            "default: the operator opts in at the command line, and a repository file never "
            "opts itself in. HTTP/SSE servers and autoApprove lists are refused, not imported"
        ),
    )
    mcp.add_argument("--mcp-server", dest="mcp_servers", action="append", default=[], metavar="NAME=COMMAND...", help="connect one MCP stdio server; its tools appear as mcp__NAME__tool and are mutating-by-default (denied until --allow-tool names them). Repeatable.")
    mcp.add_argument("--mcp-timeout-ms", type=int, default=15_000, help="per-request deadline for the MCP handshake and tool calls")
    mcp.add_argument("--mcp-protocol", choices=("auto", "legacy", "modern"), default="auto", help="which MCP protocol generation to speak: auto probes server/discover and falls back to the legacy initialize handshake only when that probe is refused")
    mcp.add_argument("--mcp-elicit", action="store_true", help="let MCP servers ask this client for input (the 2026-07-28 input_required path). Off by default: with no approver attached every request is declined, so a remote server never interviews the model instead of the operator. Answers come from --mcp-elicit-answers, else from the terminal")
    mcp.add_argument("--mcp-elicit-answers", metavar="JSON", default=None, help="pre-approved answers as a JSON object mapping field names to values, for example {\"approved\": true}. A request needing a field the set does not cover is declined rather than guessed")
    mcp.add_argument("--mcp-allow-sensitive-input", action="store_true", help="allow an MCP elicitation to ask for a password/token/secret field. Off by default: secrets do not travel through a tool transport")
    mcp.add_argument("--mcp-allow-roots", action="store_true", help="let an MCP server list workspace roots; when allowed it is offered exactly one root, the workspace itself")
    mcp.add_argument("--mcp-max-rounds", type=int, default=3, help="how many times one tool call may be re-asked for input before the client gives up")

    execution = parser.add_argument_group("execution delegation")
    execution.add_argument("--sidecar-socket", default="", help="Unix socket of northstar-codex-sidecar; enables the CodexReadOnly tool")
    execution.add_argument("--sidecar-timeout-ms", type=int, default=30_000, help="sidecar execution deadline")
    execution.add_argument("--probe-sidecar", action="store_true", help="send one health-check prompt to the sidecar and exit")

    output = parser.add_argument_group("output")
    output.add_argument("--json", action="store_true", help="emit every event as a JSONL line")
    output.add_argument("--quiet", action="store_true", help="print only the final result line")
    output.add_argument("--trace", action="store_true", help="print the span tree afterwards")
    output.add_argument("--session-dir", default="", help="append an auditable JSONL transcript here")
    output.add_argument(
        "--session-lease-seconds",
        type=int,
        default=900,
        metavar="N",
        help="how long this run promises to be alive while it owns the session transcript (renewed as the run proceeds, so a slow turn is not evicted); a live holder is never displaced, so N is a signal to readers and not a lock timeout",
    )
    output.add_argument(
        "--no-session-lease",
        action="store_true",
        help="append to the transcript without claiming it first. Two concurrent runs on one session id otherwise interleave into a file neither of them can replay; use this only where flock is unavailable, and it is reported in the transcript's init record",
    )
    output.add_argument("--resume", default="", help="session id to continue from --session-dir (appends to that same transcript)")
    output.add_argument(
        "--resume-from",
        default="",
        metavar="SESSION_ID",
        help="fork a new session from a checkpoint in --session-dir: the parent transcript is never modified",
    )
    output.add_argument(
        "--resume-record",
        type=int,
        default=None,
        metavar="INDEX",
        help="with --resume-from: resume from the checkpoint at this transcript record index (default: the latest)",
    )
    output.add_argument("--redact-tool-output", action="store_true", help="record tool results in the session without output bodies")
    output.add_argument("--stream", action="store_true", help="print (and, with --json, emit) assistant text as it arrives instead of at end of turn. Presentation only: the transcript, the permission gate, the ceilings and the single result event are unchanged, and a provider that cannot stream is refused rather than silently degraded")
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


#: The model each provider prices and requests by default when --model is omitted.
PROVIDER_DEFAULT_MODELS = {
    "scripted": "claude-sonnet-4-5",
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-4.1",
}


def resolve_model(provider: str, model: str = "") -> str:
    """The model id to use, or a configuration error for an impossible pairing.

    A claude model id against the Chat Completions adapter (or vice versa) is a
    request that is certain to fail at the server, so it is refused here, before
    any credential is read and before a turn is spent.
    """
    chosen = (model or "").strip() or PROVIDER_DEFAULT_MODELS.get(provider, "")
    if not chosen:
        raise ValueError(f"unknown provider {provider!r}; no default model is configured for it")
    if provider == "openai" and chosen.startswith("claude"):
        raise ValueError(
            f"--provider openai cannot serve {chosen!r}: pass a Chat Completions model id "
            "(e.g. --model gpt-4.1) or use --provider anthropic for Claude models"
        )
    if provider == "anthropic" and not chosen.startswith("claude"):
        raise ValueError(
            f"--provider anthropic cannot serve {chosen!r}: the Messages API speaks for Claude "
            "models; use --provider openai for Chat Completions endpoints"
        )
    return chosen


def checkpoint_usage(checkpoint: Any) -> Any:
    """The parent's token totals as a Usage, so a resumed run's cost view is continuous."""
    from providers.base import Usage

    data = getattr(checkpoint, "usage", None) or {}
    return Usage(
        input_tokens=int(data.get("input_tokens", 0) or 0),
        output_tokens=int(data.get("output_tokens", 0) or 0),
        cache_read_input_tokens=int(data.get("cache_read_input_tokens", 0) or 0),
        cache_creation_input_tokens=int(data.get("cache_creation_input_tokens", 0) or 0),
    )


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
    if args.provider == "openai":
        import os

        from providers.openai_compat import OpenAICompatProvider

        # The key comes from the environment only: a flag would put it in the
        # process list, the shell history, and any CI log that echoes argv.
        base_url = (args.base_url or os.environ.get("OPENAI_BASE_URL", "")).strip() or None
        return OpenAICompatProvider(
            model=args.model,
            base_url=base_url,
            max_tokens=args.max_output_tokens,
        )
    raise ValueError(f"unknown provider {args.provider!r}")


def _check_anthropic_sdk() -> tuple[bool, str]:
    """Whether the ``anthropic`` package is importable, and how to fix it if not.

    Imported on demand (never at module import time) so the rest of the CLI stays
    usable on hosts that only run the offline scripted provider.
    """
    if importlib.util.find_spec("anthropic") is not None:
        return True, "anthropic SDK is installed"
    return False, "the 'anthropic' package is not installed; pip install -r requirements.txt, or use --provider scripted"


def _print_dry_run(
    args: argparse.Namespace,
    runtime: Any,
    *,
    policy_note: str = "none",
    context_note: str = "off",
    workspace_agents_note: str = "none",
    skills_note: str = "none",
    plugin_note: str = "none",
    mcp_note: str = "off",
    hooks_note: str = "none",
) -> int:
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
    print(_retry_note(config))
    print(f"sidecar={'on' if config.sidecar_socket else 'off'} "
          f"session_dir={args.session_dir or 'off'} "
          f"halt_on_denial={config.halt_on_denial}")
    print(_session_lease_note(config, session_dir=args.session_dir))
    print(f"policy_file={policy_note}")
    print(f"run_id={config.run_id or '(generated per sidecar call)'} "
          f"policy_revision={config.policy_revision or '(none)'} "
          f"unwritable={','.join(config.tool_limits.protected_prefixes)}")
    print(f"project_context={context_note}")
    print(f"workspace_agents={workspace_agents_note}")
    print(f"skills={skills_note}")
    print(f"plugins={plugin_note}")
    print(f"hooks={hooks_note}")
    print(f"stream={'on' if getattr(args, 'stream', False) else 'off'}"
          + (" (assistant text as it arrives; the transcript stays turn-granular)" if getattr(args, "stream", False) else ""))
    print(f"mcp_servers={mcp_note}" + (" (not connected in dry-run)" if mcp_note != "off" else ""))
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
        from agent_files import AgentFileError, register_workspace_agents
        from agents import builtin_registry
        from tools import build_default_registry

        registry = builtin_registry()
        try:
            register_workspace_agents(registry, args.workspace, known_tools=build_default_registry().names())
        except AgentFileError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR
        for definition in registry:
            print(f"{definition.name:<12} tools={','.join(definition.tools)}")
            print(f"{'':<12} mode={definition.permission_mode} turns={definition.max_turns} verdict={definition.require_verdict}")
            print(f"{'':<12} {definition.description}")
        return 0
    if args.command == "new":
        from scaffold import scaffold_project

        try:
            created = scaffold_project(args.directory, force=args.force)
        except ValueError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR
        for path in created:
            print(f"created {path}")
        print("governed project scaffolded; start with `northstar-agent-runtime doctor --workspace <dir>`")
        return 0
    if args.command != "run":
        if args.command == "doctor":
            return run_doctor(args)
        if args.command == "sessions":
            from session_view import run_sessions

            return run_sessions(args)
        if args.command == "mcp":
            handler = getattr(args, "handler", None)
            if handler is None:
                # Bare `mcp` prints the action list rather than guessing: the one action it
                # has is read-only, but defaulting to it would teach the shape of a verb whose
                # siblings write.
                parser.parse_args([*(args.command, "list"), "--help"])
                return 0
            return handler(args)
        if args.command == "skills":
            handler = getattr(args, "handler", None)
            if handler is None:
                parser.parse_args([*(args.command, "check"), "--help"])
                return 0
            return handler(args)
        if args.command == "plugin":
            handler = getattr(args, "handler", None)
            if handler is None:
                # Bare `plugin` prints the first action's help instead of guessing an
                # action: install/verify/uninstall all write, and defaulting to one of
                # them would make "I typed less" mean "I changed the workspace".
                parser.parse_args([*(args.command, "list"), "--help"])
                return 0
            return handler(args)
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


def _retry_policy(args: argparse.Namespace, policy: Any):
    """The run's transport policy: the workspace table, then the flags, clamped to the table.

    Order matters and is the same as every other ceiling here. The repository's ``[retry]``
    table is the promise; ``--retry-*`` may shorten it and cannot lengthen it, because a flag
    that could turn "this repo waits at most twice" into "wait eight times" would make the file
    decorative. ``--no-retry`` is not ``--retry-max-attempts 1`` in disguise: it also turns
    jitter off, so the run that wanted to see the first fault sees it as early as possible.
    """
    from provider_retry import RetryConfigurationError, RetryPolicy, merge_cli

    workspace_policy = RetryPolicy.from_mapping(getattr(policy, "retry", None))
    base = workspace_policy or RetryPolicy()
    retry_on = None
    if getattr(args, "retry_on", None):
        retry_on = tuple(item.strip() for item in str(args.retry_on).split(",") if item.strip())
        if not retry_on:
            raise RetryConfigurationError("--retry-on needs at least one fault class")
    return merge_cli(
        base,
        max_attempts=getattr(args, "retry_max_attempts", None),
        deadline_ms=getattr(args, "retry_deadline_ms", None),
        retry_on=retry_on,
        off=bool(getattr(args, "no_retry", False)),
    )


def _retry_note(config: Any) -> str:
    """One dry-run line describing what a provider fault may cost this run."""
    retry = getattr(config, "retry", None)
    if retry is None:
        return "retry=off (one provider request per turn)"
    return retry.describe()


def _session_lease_note(config: Any, *, session_dir: str = "") -> str:
    """One dry-run line: could this run actually claim the transcript it means to write?

    A dry run probes the lock for the length of one syscall and drops it again, which
    answers a question no amount of config inspection can: *is another run in that file
    right now*. It is labelled "as of now" because it is a race, not a reservation - the
    load-bearing claim is the one the real run makes, and nothing here holds the file for
    anybody.
    """
    if not getattr(config, "lock_session", True):
        return "session_lease=off (--no-session-lease: the transcript is written unclaimed)"
    if not session_dir:
        return "session_lease=n/a (no --session-dir, so there is no transcript to guard)"
    from session_lease import LeaseError, inspect_lease, lease_path_for

    try:
        status = inspect_lease(lease_path_for(session_dir, config.session_id))
    except (LeaseError, OSError) as error:
        # Reporting "unknown" beats reporting "free": the second is an invitation.
        return f"session_lease=unknown (cannot read {session_dir}: {error})"
    ttl = getattr(config, "session_lease_seconds", 900)
    if status.locked:
        who = status.owner_id or "an unnamed run"
        return (
            f"session_lease=HELD by {who!r} as of now (this run would end with "
            "error_session_busy, exit 7, and write nothing)"
        )
    if status.metadata_readable and status.owner_id:
        return (
            f"session_lease=free (last owner {status.owner_id!r}); will claim for {ttl}s "
            "and renew as the run proceeds"
        )
    return f"session_lease=free; will claim for {ttl}s and renew as the run proceeds"


def _hooks_note(policy: Any, command_hooks: Sequence[Any], *, enabled: bool, plugin_hooks: int = 0) -> str:
    """One line for ``--dry-run``: what the repository declared, and whether it runs.

    The IGNORED case is spelled out on purpose. A repository that ships hooks
    and gets silence would assume they fired; a host that forgot the flag should
    see the gap in the plan, not discover it in an audit diff. Hooks contributed by
    installed bundles are counted in the same number, because the same flag gates them.
    """
    declared = (len(tuple(getattr(policy, "hooks", ()) or ())) if policy is not None else 0) + int(plugin_hooks)
    if declared == 0:
        return "none"
    if not enabled:
        return f"{declared} declared, IGNORED (pass --enable-workspace-hooks)"
    from command_hooks import summarise

    return summarise(command_hooks, enabled=True)


def _parse_mcp_servers(args: argparse.Namespace) -> list[tuple[str, list[str]]]:
    """Parse --mcp-server flags (NAME=COMMAND...) without touching the network."""
    from mcp_client import parse_mcp_flag

    return [parse_mcp_flag(value) for value in getattr(args, "mcp_servers", []) or []]


def _mcp_launch(args: argparse.Namespace) -> tuple[list[tuple[str, list[str]]], dict[str, Any], Any]:
    """The servers to start, plus the env/cwd each imported one asked for.

    Returns ``(servers, launch, report)``. ``servers`` keeps the ``(name, argv)`` shape every
    other caller of the MCP path uses - flags and plugin contributions both produce it - and
    ``launch`` carries the two per-server extras only a config file can supply. Keeping them
    apart is deliberate: inventing a parallel field for flag- and plugin-declared servers
    would suggest the runtime can grow one, and neither source has an environment to talk about.

    Two severities, matching :func:`mcp_config.read_document`. A file that cannot be
    *understood* is fatal: a run whose tool list differs silently from the one a reviewer
    approved is worse than no run. A file that describes one server we cannot start (an HTTP
    transport) is a loud warning instead, because that is a limitation of this runtime rather
    than a question about trust, and the other servers in the file are still the operator's.
    """
    from mcp_config import McpImport, McpConfigError, discover, read_document

    requested = str(getattr(args, "mcp_config", "off") or "off")
    servers = _parse_mcp_servers(args)
    if requested == "off":
        return servers, {}, None
    workspace = Path(str(getattr(args, "workspace", ".") or ".")).resolve()
    try:
        if requested == "auto":
            report = discover(workspace)
        else:
            found, refused, notes = read_document(workspace / requested, workspace=workspace)
            report = McpImport(servers=found, refused=refused, notes=notes, files=(requested,))
    except (McpConfigError, OSError, ValueError) as error:
        raise ValueError(f"mcp config: {error}") from error
    for why in report.refused:
        print(f"! mcp config: {why}", file=sys.stderr)
    for why in report.notes:
        print(f"- mcp config: {why}", file=sys.stderr)
    launch = {server.name: {"env": server.env_mapping, "cwd": server.cwd} for server in report.servers}
    clash = sorted({name for name, _argv in servers} & set(launch))
    if clash:
        raise ValueError(
            "mcp config: " + ", ".join(clash) + " declared by both --mcp-server and the workspace file; "
            "remove one - neither source may shadow the other's environment"
        )
    return [*servers, *[(server.name, list(server.argv)) for server in report.servers]], launch, report


def _mcp_stance_note(args: argparse.Namespace) -> str:
    """How this run will treat a remote server's requests, in one line.

    Printed even when everything is default, because "off" is the interesting fact: an
    auditor reading a CI log should be able to tell that no MCP server could ask this
    run for anything.
    """
    answers = getattr(args, "mcp_elicit_answers", None)
    if not getattr(args, "mcp_elicit", False):
        elicit = "elicit=off→input_required is declined"
    elif answers:
        elicit = "elicit=on→pre-approved answers only"
    else:
        elicit = "elicit=on→terminal"
    return ", ".join(
        [
            f"protocol={getattr(args, 'mcp_protocol', 'auto')}",
            elicit,
            f"roots={'on' if getattr(args, 'mcp_allow_roots', False) else 'off'}",
            f"sensitive_input={'on' if getattr(args, 'mcp_allow_sensitive_input', False) else 'off'}",
            f"rounds={getattr(args, 'mcp_max_rounds', 3)}",
        ]
    )


def _mcp_elicitor(args: argparse.Namespace) -> Any:
    """Build the approver that answers MCP input requests, if the operator allowed one."""
    if not getattr(args, "mcp_elicit", False):
        return None
    raw = getattr(args, "mcp_elicit_answers", None)
    if raw:
        from mcp_elicitation import make_answers_elicitor

        try:
            answers = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"--mcp-elicit-answers is not valid JSON: {error}") from error
        if not isinstance(answers, dict):
            raise ValueError("--mcp-elicit-answers must be a JSON object of field names to values")
        return make_answers_elicitor(answers)
    import sys

    from mcp_elicitation import make_terminal_elicitor

    if not sys.stdin or not sys.stdin.isatty():
        # A governed run must never hang waiting for a human who is not there.
        raise ValueError(
            "--mcp-elicit needs a terminal or --mcp-elicit-answers: stdin is not interactive"
        )
    return make_terminal_elicitor()


def _connect_mcp_clients(
    servers: Sequence[tuple[str, list[str]]],
    timeout_ms: int,
    registry: Any,
    args: Any = None,
    launch: dict[str, Any] | None = None,
) -> list[Any]:
    """Connect each MCP server and register its tools (mcp__<server>__<tool>).

    Every tool is mutating-by-default and needs_workspace=False, so the runtime's
    permission gate denies it under 'default' until --allow-tool names it. On any
    failure the servers opened so far are closed before the error propagates.
    """
    from mcp_client import McpStdioClient, mcp_tool_specs

    options: dict[str, Any] = {}
    if args is not None:
        options = {
            "protocol": getattr(args, "mcp_protocol", "auto"),
            "elicitor": _mcp_elicitor(args),
            "allow_sensitive_input": bool(getattr(args, "mcp_allow_sensitive_input", False)),
            "allow_roots": bool(getattr(args, "mcp_allow_roots", False)),
            "max_input_rounds": getattr(args, "mcp_max_rounds", 3),
            "workspace_root": Path.cwd(),
        }
    clients: list[Any] = []
    extras = dict(launch or {})
    try:
        for name, command in servers:
            settings = dict(extras.get(name) or {})
            unknown = sorted(set(settings) - {"env", "cwd"})
            if unknown:
                raise ValueError(f"mcp server {name!r}: unknown launch setting {unknown[0]!r}")
            client = McpStdioClient(name, command, timeout_ms=timeout_ms, **settings, **options)
            client.connect()
            if client.negotiation:
                print(f"[mcp] {name}: {client.negotiation}", file=sys.stderr)
            try:
                for spec in mcp_tool_specs(client):
                    registry.register(spec, replace_existing=False)
            except ValueError as error:
                raise ValueError(f"mcp server {name!r}: cannot register tools: {error}") from error
            clients.append(client)
    except ValueError as error:
        for client in clients:
            client.close()
        raise ValueError(f"mcp: {error}") from error
    return clients


def _run(args: argparse.Namespace) -> int:
    from agent_files import AgentFileError, register_workspace_agents
    from agents import builtin_registry
    from loop import AgentRuntime, DEFAULT_SYSTEM_PROMPT, RuntimeConfig, RuntimeConfigurationError
    from permissions import validate_mode
    from policy_file import PolicyFileError, append_project_context, discover_project_context, load_policy_file
    from sessions import SessionStore
    from skills import SkillError, discover_skills, skill_listing
    from tools import ToolLimits, build_default_registry

    try:
        args.model = resolve_model(args.provider, args.model)
    except ValueError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return USAGE_ERROR

    if args.require_skill_lock:
        from skill_check import run_lock_status

        locked, detail = run_lock_status(args.workspace)
        if not locked:
            print(f"configuration error: skill review is required and failed: {detail}", file=sys.stderr)
            return USAGE_ERROR

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

    # Installed plugin bundles (.northstar/plugins/). A bundle is a *packaging* format, not
    # a new permission channel: everything it contributes is handed to the seam that already
    # governs it (skills check rules, agent-file collisions, hook validation, MCP permission
    # gate, tighten-only ceilings), and a bundle that fails any check blocks the run instead
    # of loading "partially" - half a reviewed plugin is not a reviewed plugin.
    plugins: Any = None
    if not args.no_plugins:
        from plugin_load import load_contributions
        from plugin_manifest import PluginError

        try:
            plugins = load_contributions(args.workspace, known_tools=registry.names())
        except (PluginError, OSError, ValueError) as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR
        if plugins.blocked:
            print(
                "configuration error: installed plugins are not loadable:\n  - "
                + "\n  - ".join(str(item) for item in plugins.blocked),
                file=sys.stderr,
            )
            print(
                f"  run `python3 -m cli plugin verify --workspace {args.workspace}` to see the reviewed set, "
                "and `plugin list` to see what is installed",
                file=sys.stderr,
            )
            return USAGE_ERROR
        for note in plugins.notes:
            print(f"note: plugin: {note}", file=sys.stderr)

    # Repository-defined subagents (.northstar/agents/*.md). Governed like
    # built-ins: known tools only, tighten-only ceilings, fail-closed parse.
    workspace_agents: tuple[Any, ...] = ()
    if not args.no_workspace_agents:
        try:
            workspace_agents = register_workspace_agents(
                agents,
                args.workspace,
                known_tools=registry.names(),
                extra_paths=[path for _name, path in (plugins.agent_directories if plugins else ())],
            )
        except AgentFileError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR

    # Workspace policy file (.northstar/config.toml). It may only tighten; any
    # violation is a configuration error (exit 64), never a silent ignore.
    # Known agents include repository-defined ones, so the file may pick them.
    policy = None
    if not args.no_policy_file:
        try:
            policy = load_policy_file(args.workspace, known_tools=registry.names(), known_agents=agents.names())
        except PolicyFileError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR

    # Repository-declared lifecycle hooks. Off unless a human enables them: cloning
    # a repository must not mean executing it. Anything the file declares is
    # validated fail-closed, and an unusable declaration is a configuration error.
    hook_registry = None
    command_hooks: tuple[Any, ...] = ()
    plugin_hook_tables = tuple(table for _name, table in (plugins.hook_tables if plugins else ()))
    declared_hooks = tuple(getattr(policy, "hooks", ()) or ()) + plugin_hook_tables
    hook_source_parts = []
    if getattr(policy, "hooks", ()):
        hook_source_parts.append(str(getattr(policy, "source", "the workspace policy")))
    if plugin_hook_tables:
        hook_source_parts.append(f"{len(plugin_hook_tables)} from installed plugins")
    hook_sources = " and ".join(hook_source_parts) or "the workspace policy"
    if declared_hooks:
        from command_hooks import CommandHookError, parse_hooks, register_into

        try:
            if args.enable_workspace_hooks:
                command_hooks = parse_hooks(
                    declared_hooks,
                    workspace=args.workspace,
                    known_tools=registry.names(),
                )
                from hooks import HookRegistry

                hook_registry = HookRegistry()
                register_into(hook_registry, command_hooks, workspace=args.workspace)
            else:
                # Validated lazily, but reported loudly: silently ignoring a
                # repository's policy is exactly what this project refuses to do.
                print(
                    f"note: {len(declared_hooks)} hook(s) declared in {hook_sources} are IGNORED "
                    "(pass --enable-workspace-hooks to run them)",
                    file=sys.stderr,
                )
        except CommandHookError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR

    # Postconditions are checked after the run by this process, not by the model.
    # CLI and policy file are additive in both directions: a repository can require
    # a check, an operator can require one more, neither can drop the other's.
    postconditions: tuple[Any, ...] = ()
    declared_checks = tuple(args.verify or ()) + tuple(getattr(policy, "verify", ()) or ())
    if declared_checks:
        from postconditions import parse_cli_specs, parse_postconditions

        try:
            postconditions = parse_cli_specs(args.verify or ()) + parse_postconditions(
                tuple(getattr(policy, "verify", ()) or ()), source=str(getattr(policy, "source", "policy file"))
            )
        except ValueError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR

    cli_mode = "plan" if args.plan else args.permission_mode
    validate_mode(cli_mode)
    # The file may pin 'plan' (or keep 'default'); it may never loosen. A CLI
    # mode other than the built-in default is an explicit operator choice and
    # wins. --no-policy-file is the escape hatch for an explicit 'default'.
    # A plugin may pin 'plan' (a ceiling), never 'default' or 'bypassPermissions': the
    # policy file's own value wins over a bundle's, and an explicit operator flag wins over
    # both, because a human typing it is the only thing that can widen a mode here.
    policy_mode = policy.permission_mode if (policy is not None and policy.permission_mode is not None) else None
    plugin_mode = str(plugins.policy.get("permission_mode") or "") if plugins is not None else ""
    pinned_mode = policy_mode or plugin_mode
    mode = pinned_mode if (cli_mode == "default" and pinned_mode) else cli_mode
    validate_mode(mode)

    allowed_cli, denied_cli = _tool_lists(args, base_tools=registry.names())
    denied_list = list(denied_cli)
    if policy is not None:
        # File denials and read_only are a floor: they add to the CLI denials
        # and the permission gate's first layer keeps them terminal.
        denied_list.extend(policy.deny_tools)
        if policy.read_only:
            denied_list.extend(MUTATING_TOOLS)
    if plugins is not None and plugins.policy.get("deny_tools"):
        # A bundle may name tools it wants refused - and nothing else. There is no
        # `allow_tools` here for the same reason there is none in the policy file: an
        # artefact that arrives from elsewhere cannot grant itself approvals.
        denied_list.extend(str(name) for name in plugins.policy["deny_tools"])
    if plugins is not None and plugins.policy.get("read_only"):
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

    if (args.mcp_servers or (plugins and plugins.mcp_servers)) and definition is not None:
        # An agent-definition run fixes its tool subset by definition; silently
        # adding MCP tools to that subset would widen the declared policy.
        raise ValueError(
            "--mcp-server cannot be combined with an agent-definition run (its tool "
            "subset is fixed by the agent's definition); run without --agent to expose "
            "MCP tools on the main loop"
        )
    mcp_servers: list[tuple[str, list[str]]] = []
    mcp_launch: dict[str, Any] = {}
    mcp_report = None
    if args.mcp_servers or str(getattr(args, "mcp_config", "off") or "off") != "off":
        mcp_servers, mcp_launch, mcp_report = _mcp_launch(args)
    for server in (plugins.mcp_servers if plugins else ()):
        # A bundle's server enters the same list as an operator's flag, so it inherits the
        # whole rule set that comes with it: mutating by default, denied until named, and
        # closed on SIGTERM. Nothing here lets a plugin register a tool directly.
        mcp_servers.append((str(server["name"]), [str(server["command"]), *[str(a) for a in server.get("args") or ()]]))

    def tighten(cli_value: int | None, file_value: int | None) -> int | None:
        """Policy-file ceilings may only lower; when both are set, the lower wins."""
        candidates = [value for value in (cli_value, file_value) if value is not None]
        return min(candidates) if candidates else None

    base_turns = definition.max_turns if definition else args.max_turns
    base_tool_calls = definition.max_tool_calls if definition else args.max_tool_calls
    plugin_policy = plugins.policy if plugins is not None else {}
    max_turns = tighten(tighten(base_turns, policy.max_turns if policy is not None else None), plugin_policy.get("max_turns"))
    max_tool_calls = tighten(
        tighten(base_tool_calls, policy.max_tool_calls if policy is not None else None), plugin_policy.get("max_tool_calls")
    )
    max_budget_usd = tighten(
        tighten(args.max_budget_usd, policy.max_budget_usd if policy is not None else None), plugin_policy.get("max_budget_usd")
    )
    compaction_threshold = tighten(
        args.compaction_threshold_tokens,
        policy.compaction_threshold_tokens if policy is not None else None,
    )
    halt_on_denial = bool(
        args.halt_on_denial
        or (policy is not None and policy.halt_on_denial)
        or (plugins is not None and plugins.policy.get("halt_on_denial"))
    )

    try:
        from provider_retry import RetryConfigurationError

        retry_policy = _retry_policy(args, policy)
    except RetryConfigurationError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return USAGE_ERROR
    config_kwargs: dict[str, Any] = {
        "retry": retry_policy,
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
        "tool_limits": ToolLimits(
            # The agent's own governance is unwritable unless a human explicitly
            # says otherwise for this run (see tools.ToolLimits for why).
            protected_prefixes=(".git",) if args.allow_policy_writes else (".git", ".northstar")
        ),
        "record_tool_output_in_session": not args.redact_tool_output,
        "stream": args.stream,
    }
    if postconditions:
        config_kwargs["postconditions"] = postconditions
    if args.run_id:
        config_kwargs["run_id"] = args.run_id
    if policy is not None and policy.revision:
        config_kwargs["policy_revision"] = policy.revision
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

    # Workspace skills (.northstar/skills/*/SKILL.md): progressive disclosure -
    # only the name/description listing enters the prompt; the model reads the
    # full SKILL.md with the ordinary sandboxed Read tool when a task matches.
    skills: tuple[Any, ...] = ()
    if not args.no_skills:
        try:
            skills = discover_skills(
                args.workspace,
                extra_roots=[path for _name, path in (plugins.skill_roots if plugins else ())],
            )
        except SkillError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR
    if skills:
        base_prompt = config_kwargs.get("system_prompt", DEFAULT_SYSTEM_PROMPT)
        config_kwargs["system_prompt"] = base_prompt + skill_listing(skills, args.workspace)
    if plugins is not None and plugins.context_blocks:
        # A bundle's README-style context is the same kind of content as AGENTS.md: it
        # informs, it does not authorise. It is therefore appended after the policy and
        # labelled, so a reader of the transcript can tell whose words these are.
        base_prompt = config_kwargs.get("system_prompt", DEFAULT_SYSTEM_PROMPT)
        blocks = "\n\n".join(f"[from plugin '{name}']\n{text}" for name, text in plugins.context_blocks)
        config_kwargs["system_prompt"] = (
            base_prompt + "\n\n== Plugin context (developer-authored, from installed bundles) ==\n" + blocks + "\n== End of plugin context =="
        )
    if args.sidecar_socket:
        config_kwargs["sidecar_socket"] = args.sidecar_socket
        config_kwargs["sidecar_timeout_ms"] = args.sidecar_timeout_ms

    if args.checkpoint_turns < 0:
        print("configuration error: --checkpoint-turns must be >= 0 (0 disables checkpoints)", file=sys.stderr)
        return USAGE_ERROR
    if args.checkpoint_turns and args.checkpoint_turns > args.max_turns:
        # A cadence that can never fire would leave the operator believing the run
        # was resumable when no record was ever written.
        print(
            f"configuration error: --checkpoint-turns {args.checkpoint_turns} exceeds --max-turns {args.max_turns}, "
            "so no checkpoint could ever be written",
            file=sys.stderr,
        )
        return USAGE_ERROR
    if args.no_session_lease and args.session_lease_seconds != 900:
        print(
            "configuration error: --session-lease-seconds has no meaning with --no-session-lease; "
            "pick one (no lease, or a lease of N seconds)",
            file=sys.stderr,
        )
        return USAGE_ERROR
    if not args.no_session_lease and args.session_lease_seconds < 0:
        # 0 is the one value that means something else here: it reads as "lease for no
        # time", which is a lease that is always up for grabs. Turning it off is what
        # --no-session-lease is for, and saying so beats inventing a synonym.
        print(
            "configuration error: --session-lease-seconds must be > 0; use --no-session-lease to run without a lease",
            file=sys.stderr,
        )
        return USAGE_ERROR
    if args.resume_record is not None and not args.resume_from:
        print("configuration error: --resume-record only means something with --resume-from", file=sys.stderr)
        return USAGE_ERROR
    if args.resume and args.resume_from:
        print(
            "configuration error: choose one of --resume (append to the same transcript) or "
            "--resume-from (fork a new session from a checkpoint); they disagree about the parent file",
            file=sys.stderr,
        )
        return USAGE_ERROR
    if args.resume_from and not args.session_dir:
        print("configuration error: --resume-from needs --session-dir to read the parent transcript from", file=sys.stderr)
        return USAGE_ERROR

    from budget import Budget as _Budget

    resume_budget: Any = None
    if args.resume_from:
        from checkpoints import CheckpointError, select as select_checkpoint

        _parent_store = SessionStore(args.session_dir, session_id=args.resume_from)
        try:
            _records, _dropped = _parent_store.read(args.resume_from)
            checkpoint = select_checkpoint(_records, record_index=args.resume_record)
        except (CheckpointError, OSError, ValueError) as error:
            print(f"configuration error: cannot resume from {args.resume_from!r}: {error}", file=sys.stderr)
            return USAGE_ERROR
        if checkpoint is None:
            print(
                f"configuration error: session {args.resume_from!r} has no checkpoints "
                f"(run it with --checkpoint-turns N to make boundaries resumable)",
                file=sys.stderr,
            )
            return USAGE_ERROR
        config_kwargs["resume_from"] = checkpoint
        # A fork gets its own id and its own file; the parent stays byte-for-byte
        # what it was. --resume keeps the older append-in-place behaviour.
        config_kwargs["parent_session"] = args.resume_from
        config_kwargs["max_turns"] = max(args.max_turns, checkpoint.turns)
        # The ceiling travels with the lineage: the resumed run starts *at* what the
        # parent had already spent, so resuming cannot hand out a fresh budget.
        resume_budget = _Budget(
            max_budget_usd=args.max_budget_usd,
            total_cost_usd=checkpoint.cost_usd,
            total_usage=checkpoint_usage(checkpoint),
        )
        store = SessionStore(args.session_dir or None, session_id=None)
    else:
        store = SessionStore(args.session_dir or None, session_id=args.resume or None)
    if args.checkpoint_turns:
        config_kwargs["checkpoint_turns"] = args.checkpoint_turns
    if args.no_session_lease:
        config_kwargs["lock_session"] = False
    elif args.session_lease_seconds != 900:
        config_kwargs["session_lease_seconds"] = args.session_lease_seconds
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
            f"{policy.source} schema={policy.schema_version} revision={policy.revision or 'none'} "
            f"mode={policy.permission_mode or 'default'} "
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
    workspace_agents_note = ",".join(agent.name for agent in workspace_agents) or "none"
    hooks_note = _hooks_note(
        policy, command_hooks, enabled=args.enable_workspace_hooks, plugin_hooks=len(plugin_hook_tables)
    )
    skills_note = (f"{len(skills)} package(s): " + ", ".join(skill.name for skill in skills)) if skills else "none"
    if args.no_plugins:
        plugin_note = "off (--no-plugins)"
    elif plugins is not None and plugins.audit:
        plugin_note = (
            f"{len(plugins.audit)} bundle(s): "
            + ", ".join(f"{item['name']}@{item['version']} ({item['content_digest'][7:19]})" for item in plugins.audit)
        )
    else:
        plugin_note = "none (.northstar/plugins is empty)"
    if mcp_servers:
        listed = ", ".join(f"{name}={' '.join(command)}" for name, command in mcp_servers)
        note = _mcp_stance_note(args)
        if mcp_report is not None:
            note += f"; config {mcp_report.summary()}"
        mcp_note = f"{listed} ({note})"
    else:
        mcp_note = "off"

    provider = _build_provider(args)
    runtime = AgentRuntime(
        provider=provider,
        config=config,
        tools=registry,
        sessions=store,
        agents=agents,
        hooks=hook_registry,
        budget=resume_budget,
    )

    if args.show_pricing:
        print(json.dumps(runtime.pricing(), indent=2, sort_keys=True))
        return 0
    if args.dry_run:
        # Never constructs the provider and never connects MCP servers:
        # configuration is validated above, so a healthy configuration prints a
        # plan and exits 0 before any request or child process.
        return _print_dry_run(
            args,
            runtime,
            policy_note=policy_note,
            hooks_note=hooks_note,
            context_note=context_note,
            workspace_agents_note=workspace_agents_note,
            skills_note=skills_note,
            plugin_note=plugin_note,
            mcp_note=mcp_note,
        )
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

    # Connect MCP servers only now (never for --dry-run/--show-pricing/--probe):
    # each remote tool lands in the run's registry as a mutating-by-default
    # mcp__<server>__<tool> spec and still crosses the permission gate and hooks.
    mcp_clients: list[Any] = []
    if mcp_servers:
        try:
            mcp_clients = _connect_mcp_clients(mcp_servers, args.mcp_timeout_ms, registry, args, mcp_launch)
        except ValueError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return USAGE_ERROR
    try:
        if args.resume_from:
            resume = store.transcript(args.resume_from)
        else:
            resume = store.transcript(args.resume) if args.resume else None
        exit_code = 0
        result = None
        stream_open = False
        for event in runtime.run(prompt, resume=resume):
            if args.json:
                print(json.dumps(event_to_dict(event), ensure_ascii=False, sort_keys=True))
            else:
                _print_event(event, quiet=args.quiet, stream_open=stream_open)
            # The assistant event that follows its own deltas must not print the same
            # text a second time; the one that does not must print it normally. Tracking
            # "did the previous event stream" is the whole rule, and it lives here rather
            # than in the printer so the printer stays a pure function of one event.
            stream_open = type(event).__name__ == "StreamDelta"
            if isinstance(event, ResultMessage):
                result = event
                exit_code = EXIT_CODES.get(event.subtype, 1)
        if args.trace:
            print(runtime.tracer.tree())
        # --quiet suppresses the narration, not the result: a script wrapping the
        # CLI still gets exactly one line to parse, including the session id.
        if result is not None and not args.json:
            report = runtime.last_report
            tool_calls = len(report.tool_calls) if report is not None else 0
            print(
                f"\n[{result.subtype}] turns={result.num_turns} tool_calls={tool_calls} "
                f"cost=${result.total_cost_usd:.6f}"
                + (" (pricing estimated)" if result.pricing_estimated else "")
                + f" session={result.session_id}"
            )
            # A run that ended in error must say why; the summary line alone is a
            # dead end for whoever is reading a CI log.
            for message in result.errors:
                print(f"  ! {message}", file=sys.stderr)
            for denial in result.permission_denials:
                name = denial.get("tool", "?") if isinstance(denial, dict) else getattr(denial, "tool", "?")
                print(f"  ! refused: {name}", file=sys.stderr)
        return exit_code
    finally:
        for client in mcp_clients:
            client.close()


def _print_event(event: Any, *, quiet: bool = False, stream_open: bool = False) -> None:
    """Render one event for a human terminal.

    ``stream_open`` means "the text of this assistant turn has already been printed as it
    arrived", so the assembled message closes the line instead of repeating it. It is
    passed in rather than remembered here so this function stays stateless.
    """
    kind = type(event).__name__
    if kind == "StreamDelta":
        if not quiet:
            sys.stdout.write(event.text)
            sys.stdout.flush()
        return
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
                if stream_open:
                    # End the line the last delta left open; do not re-print the text.
                    print()
                    stream_open = False
                else:
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
