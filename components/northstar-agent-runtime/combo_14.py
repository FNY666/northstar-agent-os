"""Spec-driven toolchain, Integrated.

Combines: deliberative_spec + tool_pinning + command_registry.
Every tool invocation needs a cited spec decision, a pinned tool definition, and a registered command.

What this IS: invocations that are justified, pinned, and authorized.
What this IS NOT: a guarantee the spec itself is correct.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_14_VERSION = "combo-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-14.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


ds = _load("deliberative_spec")
tp = _load("tool_pinning")
cr = _load("command_registry")


class SpecDrivenToolchain:
    """Cite spec -> verify pin -> authorize command."""

    def __init__(self, spec: Dict[str, Any]) -> None:
        self._spec = spec
        self._pins = tp.ToolRegistry()
        self._registry = cr.CommandRegistry()

    def pin_tool(
        self, tool_id: str, definition: Dict[str, Any], pinned_by: str = "combo14"
    ) -> None:
        self._pins.pin(tool_id, definition, pinned_by=pinned_by)

    def register_command(self, name: str, autonomy: Any) -> None:
        self._registry.register(cr.CommandSpec(name, autonomy, name))

    def invoke(
        self,
        decision: str,
        cited_clauses: List[str],
        reasoning: str,
        tool_id: str,
        definition: Dict[str, Any],
        command: str,
    ) -> Dict[str, Any]:
        try:
            deliberated = ds.require_citation(
                decision, cited_clauses, reasoning, self._spec
            )
        except ds.DeliberativeError as exc:
            raise ComboError(f"uncited: {exc}") from exc
        try:
            self._pins.check_or_raise(tool_id, definition)
        except tp.ToolPinError as exc:
            raise ComboError(f"unpinned: {exc}") from exc
        ok, reason = self._registry.check(command)
        if not ok:
            raise ComboError(f"command: {reason}")
        return {"decision": deliberated, "invoked": True}


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "collections", "dataclasses", "hashlib",
        "importlib", "json", "pathlib", "re", "sys", "typing",
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
    spec = {"c1": ds.SpecClause("c1", "use pinned tools")}
    tc = SpecDrivenToolchain(spec)
    definition = {"name": "read", "v": "1"}
    tc.pin_tool("read", definition)
    tc.register_command("read", cr.AutonomyLevel.AUTOMATIC)
    r = tc.invoke("allow", ["c1"], "c1 allows", "read", definition, "read")
    assert r["invoked"] is True
    try:
        tc.invoke("allow", ["ghost"], "r", "read", definition, "read")
    except ComboError:
        pass
    else:
        raise AssertionError("uncited should fail")
    try:
        tc.invoke("allow", ["c1"], "r", "read", {"name": "read", "v": "2"}, "read")
    except ComboError:
        pass
    else:
        raise AssertionError("unpinned should fail")
    try:
        tc.invoke("allow", ["c1"], "r", "read", definition, "ghost")
    except ComboError:
        pass
    else:
        raise AssertionError("unknown command should fail")
    assert stdlib_only()
    print("combo-14 OK: cite, pin, authorize")



if __name__ == "__main__":
    main()
