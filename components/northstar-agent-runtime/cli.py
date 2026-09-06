"""Command-line entry for the agent runtime.

Offline by construction when ``--script`` is given (deterministic
ScriptedProvider, no API key). Without ``--script`` it uses the Anthropic
provider and needs ANTHROPIC_API_KEY in the environment.

Events are printed as JSON lines; exit code is 0 for a ``success`` result
subtype and 1 otherwise.

``--deny-tool`` subtracts from the computed allow list (it does not merely
add a second list that would trip the both-lists guard).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from loop import AgentRuntime, RunConfig
from permissions import PERMISSION_MODES
from tools import builtin_tools

ALLOWED_MODES = list(PERMISSION_MODES)


def computed_allow_list(permission_mode: str) -> list[str]:
    """Tools the mode auto-approves, before explicit --allow-tool/--deny-tool."""
    kinds = {t.name: t.kind for t in builtin_tools(include_codex=True)}
    if permission_mode == "bypassPermissions":
        return sorted(kinds)
    if permission_mode == "acceptEdits":
        return sorted(name for name, kind in kinds.items() if kind in ("read", "edit"))
    return sorted(name for name, kind in kinds.items() if kind == "read")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="Northstar agent runtime")
    parser.add_argument("--prompt", required=True, help="user prompt")
    parser.add_argument("--system", default="", help="system prompt")
    parser.add_argument("--workspace", default=".", help="sandbox workspace directory")
    parser.add_argument("--model", default="claude-sonnet-4-5")
    parser.add_argument("--script", help="JSON script file for the offline ScriptedProvider")
    parser.add_argument("--max-turns", type=int, default=50)
    parser.add_argument("--max-tool-calls", type=int, default=100)
    parser.add_argument("--max-budget-usd", type=float, default=None)
    parser.add_argument("--permission-mode", default="default", choices=ALLOWED_MODES)
    parser.add_argument("--allow-tool", action="append", default=[], help="explicitly allow a tool (repeatable)")
    parser.add_argument("--deny-tool", action="append", default=[], help="deny a tool; subtracted from the allow list (repeatable)")
    parser.add_argument("--sidecar-socket", default=None, help="northstar-codex-sidecar socket path (enables CodexReadOnly)")
    parser.add_argument("--session", default=None, help="append-only JSONL session file")
    parser.add_argument("--compaction-threshold-tokens", type=int, default=None)
    parser.add_argument("--max-subagent-depth", type=int, default=1)
    return parser


def build_args(args: argparse.Namespace):
    """Return (provider, RunConfig). --deny-tool subtracts from the allow list."""
    deny = set(args.deny_tool)
    allowed = [name for name in computed_allow_list(args.permission_mode) if name not in deny]
    for name in args.allow_tool:
        if name not in deny and name not in allowed:
            allowed.append(name)
    # Disjoint by construction: denied tools never remain in the allow list.
    config = RunConfig(
        model=args.model,
        system=args.system,
        workspace=Path(args.workspace),
        max_turns=args.max_turns,
        max_tool_calls=args.max_tool_calls,
        max_budget_usd=args.max_budget_usd,
        permission_mode=args.permission_mode,
        allowed_tools=tuple(allowed),
        disallowed_tools=tuple(sorted(deny)),
        sidecar_socket=args.sidecar_socket,
        session_path=Path(args.session) if args.session else None,
        compaction_threshold_tokens=args.compaction_threshold_tokens,
        max_subagent_depth=args.max_subagent_depth,
    )
    if args.script:
        from providers.scripted import ScriptedProvider

        provider = ScriptedProvider(json.loads(Path(args.script).read_text(encoding="utf-8")))
    else:
        from providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
    return provider, config


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    provider, config = build_args(args)
    runtime = AgentRuntime(provider, config)
    report = runtime.run(args.prompt)
    for event in report.events:
        print(json.dumps(event.to_dict(), ensure_ascii=False))
    return 0 if report.result.subtype == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
