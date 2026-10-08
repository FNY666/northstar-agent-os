"""DX-01: CLI framework (argparse wrapper), Simulated.

Thin, opinionated wrapper over argparse for Northstar tooling:
register named commands with handlers, get consistent help text,
fail-closed dispatch (unknown command or bad args raise, never
silently continue).

What this IS: a small command-registry + argparse bridge.
What this IS NOT: not a full CLI toolkit (no plugins, no shell
completion generation).
"""

from __future__ import annotations

import argparse
import ast
import io
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
DX01_CLI_VERSION = "dx-cli.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-cli.v1"


class CLIError(Exception):
    """Fail-closed: parse or dispatch failures raise."""


@dataclass
class Command:
    """One registered command."""

    name: str
    handler: Callable[[Dict[str, Any]], int]
    help: str = ""
    arguments: List[Dict[str, Any]] = field(default_factory=list)


class CLIApp:
    """Argparse-backed command dispatcher."""

    def __init__(self, prog: str, description: str = "") -> None:
        if not prog or not prog.strip():
            raise CLIError("prog required")
        self._prog = prog
        self._description = description
        self._commands: Dict[str, Command] = {}

    def command(
        self,
        name: str,
        help: str = "",
        arguments: Optional[List[Dict[str, Any]]] = None,
    ) -> Callable[[Callable[[Dict[str, Any]], int]], Callable[[Dict[str, Any]], int]]:
        """Decorator to register a command handler."""

        def deco(fn: Callable[[Dict[str, Any]], int]) -> Callable[[Dict[str, Any]], int]:
            if not name or not name.strip():
                raise CLIError("command name required")
            if name in self._commands:
                raise CLIError(f"duplicate command '{name}'")
            self._commands[name] = Command(
                name=name, handler=fn, help=help, arguments=arguments or []
            )
            return fn

        return deco

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog=self._prog, description=self._description)
        subs = parser.add_subparsers(dest="command", required=True)
        for cmd in self._commands.values():
            sub = subs.add_parser(cmd.name, help=cmd.help)
            for arg in cmd.arguments:
                flags = arg.get("flags", [])
                opts = {k: v for k, v in arg.items() if k != "flags"}
                sub.add_argument(*flags, **opts)
        return parser

    def parse(self, argv: List[str]) -> Dict[str, Any]:
        """Parse argv.  Raises CLIError on failure (fail-closed)."""
        parser = self._build_parser()
        try:
            ns = parser.parse_args(argv)
        except SystemExit as e:
            raise CLIError(f"argument parse failed (exit {e.code})")
        return vars(ns)

    def run(self, argv: List[str]) -> int:
        """Parse and dispatch.  Returns handler exit code."""
        parsed = self.parse(argv)
        name = parsed.pop("command")
        cmd = self._commands.get(name)
        if cmd is None:
            raise CLIError(f"unknown command '{name}'")
        try:
            return int(cmd.handler(parsed))
        except CLIError:
            raise
        except Exception as e:
            raise CLIError(f"handler for '{name}' failed: {type(e).__name__}")

    def help_text(self) -> str:
        buf = io.StringIO()
        try:
            with redirect_stdout(buf), redirect_stderr(buf):
                self._build_parser().parse_args(["--help"])
        except SystemExit:
            pass
        return buf.getvalue()

    @property
    def commands(self) -> List[str]:
        return sorted(self._commands)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "argparse", "ast", "contextlib", "dataclasses", "io", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    app = CLIApp("ns", "northstar cli")

    @app.command("ping", help="ping", arguments=[{"flags": ["--count"], "type": int, "default": 1}])
    def _ping(args: Dict[str, Any]) -> int:
        return 0 if args["count"] >= 1 else 1

    assert app.run(["ping"]) == 0
    assert app.run(["ping", "--count", "3"]) == 0
    try:
        app.run(["nope"])
        raise AssertionError("should raise")
    except CLIError:
        pass
    assert "ping" in app.help_text()
    assert stdlib_only()
    print("dx_01 OK: register, parse, dispatch, fail-closed")


if __name__ == "__main__":
    main()
