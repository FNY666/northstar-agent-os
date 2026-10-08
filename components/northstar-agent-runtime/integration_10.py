"""Integration I-010: lifecycle hooks + canary controller (hooked canary), Simulated.

Before a canary release serves traffic, the hook stack runs its canary
self-test: if any known-bad probe is NOT blocked, routing raises
(fail-closed).  A misconfigured guard stack can never be exposed to
canary traffic.

What this IS: a safety gate on canary exposure.
What this IS NOT: not the rollout verdict -- the controller routes,
the host judges canary health.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Iterable, Set

#: Module version.
INTEGRATION_10_VERSION = "integration-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-10.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_lifecycle = _load("lifecycle_hooks")
_canary = _load("canary_controller")


class IntegrationError(Exception):
    """Fail-closed."""


class GuardedCanaryRouter:
    """Routes canary traffic only after the guard self-test passes."""

    def __init__(
        self, controller: Any, pre_tool_blocklist: Iterable[str]
    ) -> None:
        if controller is None:
            raise IntegrationError("controller required")
        blocked: Set[str] = set(pre_tool_blocklist or [])
        if not blocked:
            raise IntegrationError("pre_tool_blocklist must be non-empty")
        self._controller = controller
        self._hooks = _lifecycle.HookRegistry()
        self._hooks.register(
            _lifecycle.HookPoint.PRE_TOOL,
            lambda ctx: ctx.get("tool") not in blocked,
        )

    def _probe_runner(self, tool_name: str, args: Any) -> bool:
        """True if the probe is BLOCKED by the hook stack."""
        allowed, _ = self._hooks.fire(
            _lifecycle.HookPoint.PRE_TOOL, {"tool": tool_name}
        )
        return not allowed

    def route(self, request: Any) -> Any:
        """Route a request.  Self-tests guards first if a canary is live."""
        canary = self._controller.status().canary
        if canary is not None:
            try:
                self._hooks.run_canary(self._probe_runner)
            except _lifecycle.HookError as e:
                raise IntegrationError(
                    f"canary guard self-test failed: {e}"
                )
        return self._controller.route(request)

    def deploy_canary(self, version: str, traffic_pct: float) -> Any:
        return self._controller.deploy_canary(version, traffic_pct)


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
    # No canary: routes straight to stable.
    ctrl = _canary.CanaryController("v1")
    r = GuardedCanaryRouter(ctrl, ["exec"])
    d = r.route("req-1")
    assert d.served_by == "stable"

    # Full blocklist: self-test passes, canary serves traffic.
    ctrl2 = _canary.CanaryController("v1")
    r2 = GuardedCanaryRouter(
        ctrl2, ["exec", "read_file", "send_email"]
    )
    r2.deploy_canary("v2", 100.0)
    d = r2.route("req-1")
    assert d.served_by == "canary"

    # Incomplete blocklist: fail-closed, routing raises.
    ctrl3 = _canary.CanaryController("v1")
    r3 = GuardedCanaryRouter(ctrl3, ["exec"])
    r3.deploy_canary("v2", 100.0)
    try:
        r3.route("req-1")
        raise AssertionError("should raise")
    except IntegrationError:
        pass

    assert stdlib_only()
    print("integration-10 OK: hooked canary, self-test gate, stdlib")


if __name__ == "__main__":
    main()
