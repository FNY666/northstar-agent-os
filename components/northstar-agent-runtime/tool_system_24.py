"""Tool health checks: registered checkables per tool, Simulated.

HealthChecker registers named checks (callables returning bool) per
tool.  run() executes every check; a check that returns a falsy value
or raises (a timeout is simulated by raising) marks its tool
unhealthy.  details() reports the last per-check outcome per tool;
summary() counts healthy vs unhealthy tools.

What this IS:
* In-process health polling with per-tool aggregation (Simulated).

What this IS NOT:
* Not live probing -- checks are caller-supplied callables.
* Not a load balancer -- unhealthy tools are only reported.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Callable, Dict, List

#: Module version.
TOOL_SYSTEM_24_VERSION = "tool-system-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-24.v1"


class ToolSystem24Error(Exception):
    """Fail-closed."""


@dataclass
class _Check:
    name: str
    fn: Callable[[], bool]


class HealthChecker:
    """Runs registered per-tool health checks (Simulated)."""

    def __init__(self) -> None:
        self._checks: Dict[str, List[_Check]] = {}
        self._last: Dict[str, Dict[str, bool]] = {}

    def register(
        self, tool: str, name: str, check: Callable[[], bool]
    ) -> None:
        if not tool:
            raise ToolSystem24Error("tool required")
        if not name:
            raise ToolSystem24Error("check name required")
        if not callable(check):
            raise ToolSystem24Error("check must be callable")
        self._checks.setdefault(tool, []).append(_Check(name, check))

    def checks(self, tool: str) -> List[str]:
        return [c.name for c in self._checks.get(tool, [])]

    def run(self) -> Dict[str, bool]:
        """Execute all checks; returns per-tool healthy/unhealthy."""
        results: Dict[str, bool] = {}
        for tool, checks in self._checks.items():
            detail: Dict[str, bool] = {}
            for check in checks:
                try:
                    detail[check.name] = bool(check.fn())
                except Exception:
                    detail[check.name] = False
            self._last[tool] = detail
            results[tool] = all(detail.values())
        return results

    def details(self, tool: str) -> Dict[str, bool]:
        return dict(self._last.get(tool, {}))

    def summary(self) -> Dict[str, int]:
        results = {
            tool: all(detail.values())
            for tool, detail in self._last.items()
        }
        healthy = sum(1 for ok in results.values() if ok)
        return {
            "tools": len(results),
            "healthy": healthy,
            "unhealthy": len(results) - healthy,
        }


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "typing"}
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
    hc = HealthChecker()
    hc.register("search", "ping", lambda: True)
    hc.register("search", "quota", lambda: True)
    hc.register("files", "ping", lambda: True)
    assert hc.checks("search") == ["ping", "quota"]
    assert hc.checks("nope") == []
    results = hc.run()
    assert results == {"search": True, "files": True}
    assert hc.summary() == {"tools": 2, "healthy": 2, "unhealthy": 0}
    # A failing check marks its tool unhealthy.
    hc.register("files", "disk", lambda: False)
    results = hc.run()
    assert results == {"search": True, "files": False}
    assert hc.details("files") == {"ping": True, "disk": False}
    assert hc.summary() == {"tools": 2, "healthy": 1, "unhealthy": 1}
    # A raising check (simulated timeout) also marks unhealthy.
    def boom() -> bool:
        raise TimeoutError("simulated timeout")

    hc.register("search", "slow", boom)
    results = hc.run()
    assert results["search"] is False
    assert hc.details("search")["slow"] is False
    # Bad registration.
    try:
        hc.register("", "ping", lambda: True)
        raise AssertionError("should raise")
    except ToolSystem24Error:
        pass
    try:
        hc.register("t", "ping", "not-callable")  # type: ignore[arg-type]
        raise AssertionError("should raise")
    except ToolSystem24Error:
        pass
    assert stdlib_only()
    print("tool_system_24 OK: register, run, summary")


if __name__ == "__main__":
    main()
