"""obs_28: Chaos engineering (mock), Simulated.

ChaosExperiment(name, hypothesis, steady_state_check, faults,
rollback): run() first verifies steady state (abort if not steady),
applies faults via mock callables recording effects, re-checks steady
state, then runs rollback.  Returns a result dict with hypothesis_held.

Fail-closed: non-callable steady-state check, fault, or rollback raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, Dict, List, Tuple

OBS28_VERSION = "obs-28.v1"
SCHEMA_PIN = "northstar.obs-28.v1"


class Obs28Error(Exception):
    """Fail-closed."""


class ChaosExperiment:
    """Mock chaos experiment: all faults are caller-provided callables."""

    def __init__(
        self,
        name: str,
        hypothesis: str,
        steady_state_check: Callable[[], bool],
        faults: List[Tuple[str, Callable[[], Any]]],
        rollback: Callable[[], Any],
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise Obs28Error("name must be a non-empty string")
        if not isinstance(hypothesis, str) or not hypothesis.strip():
            raise Obs28Error("hypothesis must be a non-empty string")
        if not callable(steady_state_check):
            raise Obs28Error("steady_state_check must be callable")
        if not isinstance(faults, list) or not faults:
            raise Obs28Error("faults must be a non-empty list of (label, callable)")
        for f in faults:
            if not isinstance(f, (list, tuple)) or len(f) != 2:
                raise Obs28Error("each fault must be (label, fault_callable)")
            label, fault_callable = f
            if not isinstance(label, str) or not label:
                raise Obs28Error("fault label must be a non-empty string")
            if not callable(fault_callable):
                raise Obs28Error(f"fault '{label}' must be callable")
        if not callable(rollback):
            raise Obs28Error("rollback must be callable")
        self.name = name
        self.hypothesis = hypothesis
        self.steady_state_check = steady_state_check
        self.faults = faults
        self.rollback = rollback

    def run(self) -> Dict[str, Any]:
        """Execute the experiment.  Returns result dict."""
        steady_before = bool(self.steady_state_check())
        if not steady_before:
            return {
                "name": self.name,
                "aborted": True,
                "reason": "system not in steady state before experiment",
                "hypothesis_held": False,
                "fault_effects": [],
                "rolled_back": False,
            }
        effects: List[Dict[str, Any]] = []
        for label, fault_callable in self.faults:
            try:
                effect = fault_callable()
                effects.append({"label": label, "effect": effect, "error": None})
            except Exception as exc:
                effects.append({"label": label, "effect": None, "error": str(exc)})
        steady_after = bool(self.steady_state_check())
        rolled_back = False
        rollback_error = None
        try:
            self.rollback()
            rolled_back = True
        except Exception as exc:
            rollback_error = str(exc)
        return {
            "name": self.name,
            "aborted": False,
            "reason": None,
            "hypothesis_held": steady_before and steady_after,
            "fault_effects": effects,
            "rolled_back": rolled_back,
            "rollback_error": rollback_error,
        }


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
    healthy = [True]
    log: List[str] = []

    def check() -> bool:
        return healthy[0]

    def fault_a() -> str:
        healthy[0] = True
        log.append("a")
        return "pod deleted (mock)"

    def fault_b() -> str:
        log.append("b")
        return "latency added (mock)"

    def rollback() -> str:
        log.append("rollback")
        return "restored"

    exp = ChaosExperiment(
        "kill-pod",
        "service stays available during pod loss",
        check,
        [("kill-pod", fault_a), ("add-latency", fault_b)],
        rollback,
    )
    res = exp.run()
    assert res["hypothesis_held"] is True and res["rolled_back"] is True
    assert len(res["fault_effects"]) == 2
    assert log == ["a", "b", "rollback"]

    bad = ChaosExperiment("x", "h", lambda: False, [("f", fault_a)], rollback)
    res2 = bad.run()
    assert res2["aborted"] is True and res2["hypothesis_held"] is False

    try:
        ChaosExperiment("x", "h", "not-callable", [("f", fault_a)], rollback)  # type: ignore
        raise AssertionError("should raise")
    except Obs28Error:
        pass
    try:
        ChaosExperiment("x", "h", check, [("f", 123)], rollback)  # type: ignore
        raise AssertionError("should raise")
    except Obs28Error:
        pass
    try:
        ChaosExperiment("x", "h", check, [("f", fault_a)], None)  # type: ignore
        raise AssertionError("should raise")
    except Obs28Error:
        pass
    try:
        ChaosExperiment("x", "h", check, [], rollback)
        raise AssertionError("should raise")
    except Obs28Error:
        pass
    assert stdlib_only()
    print("obs_28 OK")


if __name__ == "__main__":
    main()
