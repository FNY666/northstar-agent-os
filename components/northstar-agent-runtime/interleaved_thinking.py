"""Interleaved thinking: enforced reasoning before tool calls, Simulated.

The runtime protocol forces the model to write explicit reasoning before
every tool call.  Reasoning is a first-class, logged artifact -- not
optional chain-of-thought.

Measured: +40% on BrowseComp (Moonshot/Kimi).

Why valuable: reasoning becomes auditable by construction.  No silent
tool calls -- every action has a stated rationale in the trace.

Mechanism: the runner rejects any tool call without a preceding
reasoning block in the same turn.  The reasoning is hashed into the
ledger entry alongside the action.

What this IS: cheap, high-value auditability.

What this IS NOT:
* Not a judge of reasoning quality -- just enforces presence.
* The reasoning content is not validated (that's the observer's job).
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

#: Module version.
INTERLEAVED_VERSION = "interleaved-thinking.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.interleaved-thinking.v1"


class InterleavedError(Exception):
    """Fail-closed: missing reasoning raises."""


@dataclass(frozen=True)
class ReasonedAction:
    """A tool call with its preceding reasoning."""

    reasoning: str
    tool_name: str
    args: Dict[str, Any]
    reasoning_hash: str


def require_reasoning(
    reasoning: Optional[str],
    tool_name: str,
    args: Dict[str, Any],
) -> ReasonedAction:
    """Enforce reasoning-before-action.

    Raises InterleavedError if reasoning is missing or empty.
    Returns ReasonedAction with the reasoning hash.

    The hash binds the reasoning to the action for ledger sealing.
    """
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise InterleavedError(
            f"tool '{tool_name}' called without preceding reasoning"
        )
    if not tool_name:
        raise InterleavedError("tool_name required")
    # Hash the reasoning for the ledger.
    reasoning_hash = "sha256:" + hashlib.sha256(
        reasoning.encode("utf-8")
    ).hexdigest()
    return ReasonedAction(
        reasoning=reasoning,
        tool_name=tool_name,
        args=dict(args) if args else {},
        reasoning_hash=reasoning_hash,
    )


class InterleavedRunner:
    """Wraps a tool executor with reasoning enforcement.

    Every tool call must be preceded by reasoning.  The reasoning is
    logged (via the provided log_fn) alongside the action.
    """

    def __init__(
        self,
        executor: Any,
        log_fn: Any = None,
    ) -> None:
        if not callable(executor):
            raise InterleavedError("executor must be callable")
        self._executor = executor
        self._log_fn = log_fn
        self._actions: List[ReasonedAction] = []

    def run(
        self,
        reasoning: Optional[str],
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Run a tool with enforced reasoning.

        Raises InterleavedError if reasoning is missing.
        Logs the ReasonedAction if log_fn was provided.
        Returns the executor's result.
        """
        action = require_reasoning(reasoning, tool_name, args or {})
        self._actions.append(action)
        if self._log_fn is not None:
            try:
                self._log_fn(action)
            except Exception:
                pass  # log failure doesn't block execution
        return self._executor(tool_name, action.args)

    @property
    def actions(self) -> List[ReasonedAction]:
        """All reasoned actions taken (for audit)."""
        return list(self._actions)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "pathlib", "typing"}
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
    """Self-check."""
    # Reasoning required.
    action = require_reasoning("I need to read the file", "read_file", {"p": "/x"})
    assert action.reasoning_hash.startswith("sha256:")
    assert action.tool_name == "read_file"

    # Missing reasoning raises.
    try:
        require_reasoning("", "tool", {})
        raise AssertionError("should raise")
    except InterleavedError:
        pass
    try:
        require_reasoning(None, "tool", {})  # type: ignore
        raise AssertionError("should raise")
    except InterleavedError:
        pass

    # Runner enforces.
    logged = []
    runner = InterleavedRunner(
        executor=lambda t, a: f"ran {t}",
        log_fn=logged.append,
    )
    result = runner.run("because I need to", "my_tool", {"x": 1})
    assert result == "ran my_tool"
    assert len(logged) == 1
    assert logged[0].tool_name == "my_tool"

    # Runner rejects without reasoning.
    try:
        runner.run("", "bad_tool", {})
        raise AssertionError("should raise")
    except InterleavedError:
        pass

    assert stdlib_only()
    print("interleaved-thinking OK: enforced reasoning, hashed, logged")


if __name__ == "__main__":
    main()
