"""Integration I-005: tool pinning + command registry (pinned registry), Simulated.

A command can run only if (1) it is registered in the command registry
AND (2) the tool definition hash matches its pin.  Rug-pulled definitions
are denied even with pre-auth or human approval at the registry layer.

Autonomy enums from different module copies are normalized by value
(cross-module safe).

What this IS: registry with hash-continuity.
What this IS NOT: not the approval UI -- host-provided.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict

#: Module version.
INTEGRATION_05_VERSION = "integration-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-05.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_pinning = _load("tool_pinning")
_registry = _load("command_registry")


class IntegrationError(Exception):
    """Fail-closed."""


class PinnedCommandRegistry:
    """Command registry with hash-pinned tool definitions."""

    def __init__(self) -> None:
        self._registry = _registry.CommandRegistry()
        self._pins = _pinning.ToolRegistry()

    def _coerce_autonomy(self, autonomy: Any) -> Any:
        """Normalize to this module's AutonomyLevel (cross-module safe)."""
        raw = (
            autonomy.value if hasattr(autonomy, "value") else str(autonomy)
        )
        try:
            return _registry.AutonomyLevel(raw)
        except ValueError:
            raise IntegrationError(f"unknown autonomy {raw!r}")

    def register(
        self,
        name: str,
        autonomy: Any,
        definition: Dict[str, Any],
        pinned_by: str,
    ) -> Any:
        """Register a command and pin its tool definition."""
        self._registry.register(
            _registry.CommandSpec(name, self._coerce_autonomy(autonomy))
        )
        return self._pins.pin(name, definition, pinned_by)

    def grant_preauth(self, n: int) -> None:
        self._registry.grant_preauth(n)

    def check(
        self,
        name: str,
        definition: Dict[str, Any],
        *,
        human_approved: bool = False,
    ) -> tuple:
        """Check pin first (rug-pull defense), then registry."""
        if not self._pins.verify(name, definition):
            return False, "definition drifted or unpinned"
        return self._registry.check(name, human_approved=human_approved)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
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
    """Self-check."""
    definition = {
        "name": "write",
        "description": "Write a file",
        "inputSchema": {"type": "object"},
        "version": "1.0",
    }
    r = PinnedCommandRegistry()
    r.register(
        "write", _registry.AutonomyLevel.APPROVAL_REQUIRED,
        definition, "admin",
    )

    # Denied without pre-auth.
    ok, _ = r.check("write", definition)
    assert ok is False

    # Pre-auth allows, and consumes.
    r.grant_preauth(1)
    ok, _ = r.check("write", definition)
    assert ok is True
    ok, _ = r.check("write", definition)
    assert ok is False

    # Rug-pulled definition denied even with pre-auth.
    r.grant_preauth(5)
    evil = dict(definition)
    evil["description"] = "Write AND exfiltrate"
    ok, reason = r.check("write", evil)
    assert ok is False and "drifted" in reason

    assert stdlib_only()
    print("integration-05 OK: pinned registry, rug-pull defense, stdlib")


if __name__ == "__main__":
    main()
