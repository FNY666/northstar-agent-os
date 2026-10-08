"""Tool playground (mock): sandboxed dry-run of a tool call, Simulated.

A Playground validates a tool call's args against a declared schema
(required keys and types), rejects unsafe arg patterns (dunder keys),
then runs a fake executor callable.  Nothing touches real tools.
The last N runs are kept in an in-memory log.

What this IS:
* Simulated dry-run harness for tool-call shape validation.

What this IS NOT:
* Not a sandbox -- the fake executor runs in-process.
* Not a substitute for real tool execution.
* Never touches real tools or external systems.
"""

from __future__ import annotations

import ast
import copy
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Deque, List, Optional

#: Module version.
TOOL_SYSTEM_26_VERSION = "tool-system-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-26.v1"

#: Keys matching this pattern are rejected as unsafe.
_UNSAFE_KEY = re.compile(r"(^__|__)")


class ToolSystem26Error(Exception):
    """Fail-closed."""


class SchemaViolation(ToolSystem26Error):
    """Raised when args do not match the declared schema."""


class UnsafeArgs(ToolSystem26Error):
    """Raised when args contain unsafe (dunder-style) keys."""


class UnknownTool(ToolSystem26Error):
    """Raised when no schema is registered for a tool."""


@dataclass
class ArgSchema:
    """Declared argument shape for one tool (mock)."""

    required: Dict[str, type] = field(default_factory=dict)
    optional: Dict[str, type] = field(default_factory=dict)


@dataclass
class DryRunRecord:
    """One recorded dry-run (mock)."""

    tool: str
    args: Dict[str, Any]
    result: Any
    ok: bool
    seq: int


class Playground:
    """Simulated dry-run executor with schema validation and run log."""

    def __init__(self, max_log: int = 50) -> None:
        if max_log <= 0:
            raise ToolSystem26Error("max_log must be positive")
        self._schemas: Dict[str, ArgSchema] = {}
        self._log: Deque[DryRunRecord] = deque(maxlen=max_log)
        self._seq = 0

    def register_schema(self, tool: str, schema: ArgSchema) -> None:
        if not tool:
            raise ToolSystem26Error("tool required")
        self._schemas[tool] = schema

    def _check_unsafe(self, value: Any, path: str = "$") -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                if isinstance(key, str) and _UNSAFE_KEY.search(key):
                    raise UnsafeArgs(f"unsafe arg key {path}.{key}")
                self._check_unsafe(val, f"{path}.{key}")
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                self._check_unsafe(item, f"{path}[{i}]")

    def _check_schema(self, tool: str, args: Dict[str, Any]) -> None:
        schema = self._schemas[tool]
        for key, want in schema.required.items():
            if key not in args:
                raise SchemaViolation(f"missing required arg '{key}'")
            if not isinstance(args[key], want):
                raise SchemaViolation(
                    f"arg '{key}' expected {want.__name__}, "
                    f"got {type(args[key]).__name__}"
                )
        for key, want in schema.optional.items():
            if key in args and not isinstance(args[key], want):
                raise SchemaViolation(
                    f"arg '{key}' expected {want.__name__}, "
                    f"got {type(args[key]).__name__}"
                )
        known = set(schema.required) | set(schema.optional)
        for key in args:
            if key not in known:
                raise SchemaViolation(f"unexpected arg '{key}'")

    @staticmethod
    def _sanitize(result: Any) -> Any:
        """Deep-copy and bound the result; Simulated, no real scrubbing."""
        result = copy.deepcopy(result)

        def _trim(value: Any, depth: int) -> Any:
            if depth > 8:
                return "<truncated>"
            if isinstance(value, str) and len(value) > 4096:
                return value[:4096] + "<truncated>"
            if isinstance(value, dict):
                return {k: _trim(v, depth + 1) for k, v in value.items()}
            if isinstance(value, list):
                return [_trim(v, depth + 1) for v in value[:100]]
            return value

        return _trim(result, 0)

    def dry_run(
        self,
        tool: str,
        args: Dict[str, Any],
        executor: Callable[[str, Dict[str, Any]], Any],
    ) -> Any:
        """Validate args, run the fake executor, log and return sanitized result."""
        if tool not in self._schemas:
            raise UnknownTool(f"no schema for tool '{tool}'")
        if not isinstance(args, dict):
            raise ToolSystem26Error("args must be a dict")
        self._check_unsafe(args)
        self._check_schema(tool, args)
        raw = executor(tool, copy.deepcopy(args))
        result = self._sanitize(raw)
        self._seq += 1
        self._log.append(
            DryRunRecord(
                tool=tool,
                args=copy.deepcopy(args),
                result=result,
                ok=True,
                seq=self._seq,
            )
        )
        return result

    def runs(self) -> List[DryRunRecord]:
        return list(self._log)

    def last_run(self) -> Optional[DryRunRecord]:
        return self._log[-1] if self._log else None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "collections",
        "copy",
        "dataclasses",
        "pathlib",
        "re",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    pg = Playground(max_log=2)
    pg.register_schema(
        "search", ArgSchema(required={"query": str}, optional={"limit": int})
    )
    out = pg.dry_run(
        "search",
        {"query": "agent", "limit": 3},
        lambda tool, args: {"hits": [args["query"]]},
    )
    assert out == {"hits": ["agent"]}
    assert pg.last_run() is not None and pg.last_run().ok
    # Missing required.
    try:
        pg.dry_run("search", {}, lambda t, a: None)
        raise AssertionError("should raise")
    except SchemaViolation:
        pass
    # Wrong type.
    try:
        pg.dry_run("search", {"query": 5}, lambda t, a: None)
        raise AssertionError("should raise")
    except SchemaViolation:
        pass
    # Unsafe dunder key.
    try:
        pg.dry_run(
            "search", {"query": "x", "__class__": 1}, lambda t, a: None
        )
        raise AssertionError("should raise")
    except UnsafeArgs:
        pass
    # Unknown tool.
    try:
        pg.dry_run("nope", {}, lambda t, a: None)
        raise AssertionError("should raise")
    except UnknownTool:
        pass
    # Log bounded to last N.
    pg.dry_run("search", {"query": "a"}, lambda t, a: {"n": 1})
    pg.dry_run("search", {"query": "b"}, lambda t, a: {"n": 2})
    assert len(pg.runs()) == 2
    assert stdlib_only()
    print("tool_system_26 OK: validate, dunder-reject, dry-run, log")


if __name__ == "__main__":
    main()
