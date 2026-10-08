"""Integration I-009: resource defense + two-tier gating (resourced gating), Simulated.

Tier-1 is the resource score: clean calls score 0.1 (allow), resource
violations (nesting/repetition/size) score 0.95 (deny).  Scores in the
gray zone can escalate to a host Tier-2 analyzer.

What this IS: DoS detection inside the fast tier.
What this IS NOT: not the enforcer of actual limits (timeouts, caps).
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

#: Module version.
INTEGRATION_09_VERSION = "integration-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-09.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_resource = _load("resource_defense")
_twotier = _load("two_tier_gating")


class IntegrationError(Exception):
    """Fail-closed."""


def resource_tier1(tool_name: str, args: Dict[str, Any]) -> float:
    """Tier-1 suspicion score from resource checks.

    0.1 for clean calls, 0.95 for resource violations.
    """
    try:
        ok, _ = _resource.check_resources(tool_name, args)
    except Exception:
        ok = False  # fail-closed: max suspicion
    return 0.1 if ok else 0.95


class ResourcedGate:
    """Two-tier gate with resource defense as Tier-1."""

    def __init__(
        self,
        tier2_fn: Optional[Callable] = None,
        *,
        escalate_threshold: float = 0.5,
        deny_threshold: float = 0.8,
    ) -> None:
        self._gate = _twotier.TwoTierGate(
            resource_tier1,
            tier2_fn,
            escalate_threshold=escalate_threshold,
            deny_threshold=deny_threshold,
        )

    def check(self, tool_name: str, args: Dict[str, Any]) -> Any:
        return self._gate.check(tool_name, args)

    @property
    def stats(self) -> Dict[str, int]:
        return self._gate.stats


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
    gate = ResourcedGate()

    # Clean call: Tier-1 allow.
    v = gate.check("read", {"path": "/x"})
    assert v.decision == "allow" and v.tier == 1

    # Recursion bomb: Tier-1 deny.
    v = gate.check("expand", {"input": "expand(" * 10})
    assert v.decision == "deny" and v.tier == 1

    # Oversized payload: deny.
    v = gate.check("send", {"blob": "x" * 200000})
    assert v.decision == "deny"

    assert gate.stats["tier1"] >= 3

    assert stdlib_only()
    print("integration-09 OK: resourced gating, bombs denied, stdlib")


if __name__ == "__main__":
    main()
