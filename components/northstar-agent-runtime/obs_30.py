"""obs_30: Fault injection (mock), Simulated.

FaultInjector registers faults (latency/error/kill) against named
targets and applies them to mock callables: latency records a fake
delay, error raises an injected error, kill marks the target dead.
Guardrail: max_targets caps the blast radius; exceeding it raises.

Fail-closed: unknown fault type, non-callable, or guardrail breach raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, Dict, List

OBS30_VERSION = "obs-30.v1"
SCHEMA_PIN = "northstar.obs-30.v1"

FAULT_TYPES = ("latency", "error", "kill")


class Obs30Error(Exception):
    """Fail-closed."""


class FaultInjector:
    """Mock fault injector with a blast-radius guardrail."""

    def __init__(self, max_targets: int = 3) -> None:
        if not isinstance(max_targets, int) or max_targets < 1:
            raise Obs30Error("max_targets must be a positive int")
        self.max_targets = max_targets
        self._faults: Dict[str, Dict[str, Any]] = {}
        self._dead: Dict[str, bool] = {}

    def inject(self, target: str, fault_type: str, params: Dict[str, Any] | None = None) -> None:
        """Register a fault on a target."""
        if not isinstance(target, str) or not target.strip():
            raise Obs30Error("target must be a non-empty string")
        if fault_type not in FAULT_TYPES:
            raise Obs30Error(f"unknown fault type '{fault_type}'; must be one of {FAULT_TYPES}")
        params = dict(params or {})
        if fault_type == "latency":
            delay_ms = params.get("delay_ms", 100)
            if not isinstance(delay_ms, (int, float)) or delay_ms < 0:
                raise Obs30Error("latency params need non-negative delay_ms")
            params["delay_ms"] = delay_ms
        elif fault_type == "error":
            message = params.get("message", "injected error")
            if not isinstance(message, str) or not message:
                raise Obs30Error("error params need a non-empty message")
            params["message"] = message
        if target not in self._faults and len(self._faults) >= self.max_targets:
            raise Obs30Error(
                f"guardrail: max_targets={self.max_targets} exceeded by '{target}'"
            )
        self._faults[target] = {"type": fault_type, "params": params}

    def is_dead(self, target: str) -> bool:
        return self._dead.get(target, False)

    def apply(self, target: str, call: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a mock callable with the target's registered fault."""
        if not callable(call):
            raise Obs30Error("call must be callable")
        fault = self._faults.get(target)
        if fault is None:
            return call
        fault_type = fault["type"]
        params = fault["params"]

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if fault_type == "latency":
                result = call(*args, **kwargs)
                return {"result": result, "injected_delay_ms": params["delay_ms"], "target": target}
            if fault_type == "error":
                raise Obs30Error(f"injected error on '{target}': {params['message']}")
            if fault_type == "kill":
                self._dead[target] = True
                return {"target": target, "dead": True, "call_skipped": True}
            raise Obs30Error("unreachable")

        return wrapped

    def blast_radius(self) -> int:
        """Number of targets with registered faults."""
        return len(self._faults)

    def targets(self) -> List[str]:
        return list(self._faults)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    inj = FaultInjector(max_targets=2)
    inj.inject("svc-a", "latency", {"delay_ms": 250})
    inj.inject("svc-b", "error", {"message": "boom"})
    assert inj.blast_radius() == 2

    out = inj.apply("svc-a", lambda: "ok")()
    assert out == {"result": "ok", "injected_delay_ms": 250, "target": "svc-a"}

    try:
        inj.apply("svc-b", lambda: "ok")()
        raise AssertionError("should raise")
    except Obs30Error as e:
        assert "boom" in str(e)

    inj2 = FaultInjector(max_targets=5)
    inj2.inject("svc-c", "kill", {})
    killed = inj2.apply("svc-c", lambda: "should not run")()
    assert killed["dead"] is True and inj2.is_dead("svc-c") is True

    passthrough = inj2.apply("svc-unknown", lambda: 42)
    assert passthrough() == 42

    try:
        inj.inject("svc-c", "latency", {})
        raise AssertionError("should raise")
    except Obs30Error:
        pass
    try:
        inj.inject("svc-d", "warp", {})
        raise AssertionError("should raise")
    except Obs30Error:
        pass
    try:
        inj.inject("svc-d", "latency", {"delay_ms": -5})
        raise AssertionError("should raise")
    except Obs30Error:
        pass
    try:
        inj.apply("svc-a", "not-callable")  # type: ignore
        raise AssertionError("should raise")
    except Obs30Error:
        pass
    try:
        FaultInjector(max_targets=0)
        raise AssertionError("should raise")
    except Obs30Error:
        pass
    assert stdlib_only()
    print("obs_30 OK")


if __name__ == "__main__":
    main()
