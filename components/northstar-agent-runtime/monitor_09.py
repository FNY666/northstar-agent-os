"""SOAR playbooks: mock response workflows, Simulated.

A Playbook is an ordered list of Steps. Each step has an action
(log, block_tool, quarantine_session, notify, escalate), optional
condition on the context, and records its outcome in a run report.

What this IS: deterministic incident-response runbooks triggered by
alerts (e.g. deny-spike -> quarantine session + notify).

What this IS NOT:
* Not a live SOAR platform -- actions are recorded, not executed
  against real infrastructure. Host maps actions to real APIs.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
MONITOR_09_VERSION = "monitor-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-09.v1"

_VALID_ACTIONS = {"log", "block_tool", "quarantine_session", "notify", "escalate"}


class PlaybookError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Step:
    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    # Condition receives context; step runs only if True (None = always).
    condition: Optional[Callable[[Dict[str, Any]], bool]] = field(
        default=None, compare=False
    )

    def __post_init__(self) -> None:
        if not self.name:
            raise PlaybookError("step name required")
        if self.action not in _VALID_ACTIONS:
            raise PlaybookError(f"bad action {self.action!r}")
        if self.condition is not None and not callable(self.condition):
            raise PlaybookError("condition must be callable")


@dataclass
class Playbook:
    name: str
    trigger: str
    steps: List[Step] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name or not self.trigger:
            raise PlaybookError("playbook name and trigger required")

    def add_step(self, step: Step) -> None:
        if not isinstance(step, Step):
            raise PlaybookError("step must be Step")
        self.steps.append(step)

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute steps in order. Returns a run report."""
        if not isinstance(context, dict):
            raise PlaybookError("context must be dict")
        executed: List[Dict[str, Any]] = []
        for step in self.steps:
            if step.condition is not None:
                try:
                    if not step.condition(context):
                        continue
                except Exception as e:
                    # Condition failure -> fail-closed: stop the playbook.
                    return {
                        "playbook": self.name,
                        "status": "aborted",
                        "reason": f"condition error in {step.name}: {e}",
                        "executed": executed,
                    }
            executed.append(
                {"step": step.name, "action": step.action, "params": step.params}
            )
        return {
            "playbook": self.name,
            "status": "completed",
            "executed": executed,
        }


def deny_spike_playbook() -> Playbook:
    """Prebuilt: on deny spike, quarantine the session and notify."""
    pb = Playbook(name="deny-spike-response", trigger="deny-spike")
    pb.add_step(Step("record", "log", {"msg": "deny spike detected"}))
    pb.add_step(
        Step(
            "quarantine",
            "quarantine_session",
            {},
            condition=lambda ctx: ctx.get("risk_score", 0) >= 50,
        )
    )
    pb.add_step(Step("notify", "notify", {"channel": "security"}))
    return pb


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    pb = deny_spike_playbook()
    rep = pb.run({"risk_score": 80})
    assert rep["status"] == "completed"
    assert [s["step"] for s in rep["executed"]] == ["record", "quarantine", "notify"]
    rep2 = pb.run({"risk_score": 10})
    assert [s["step"] for s in rep2["executed"]] == ["record", "notify"]
    # Condition raising aborts fail-closed.
    pb2 = Playbook(name="x", trigger="y")
    pb2.add_step(
        Step("bad", "log", {}, condition=lambda ctx: 1 / 0)  # type: ignore[return-value]
    )
    rep3 = pb2.run({})
    assert rep3["status"] == "aborted"
    try:
        Step("x", "bogus_action")
        raise AssertionError("should raise")
    except PlaybookError:
        pass
    try:
        pb.run("not-a-dict")  # type: ignore[arg-type]
        raise AssertionError("should raise")
    except PlaybookError:
        pass
    assert stdlib_only()
    print("monitor-09 OK: playbooks, conditions, abort, fail-closed, stdlib")


if __name__ == "__main__":
    main()
