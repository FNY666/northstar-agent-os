"""Tool blue-green deploys: two-slot state machine, Simulated.

BlueGreenDeploy keeps two slots, 'blue' and 'green'.  A new version is
deployed to the inactive slot, then switch() swaps the active slot.
Switch history is recorded with timestamps.  route() reports which
version is currently active.

What this IS:
* A pure state machine for blue/green version routing (Simulated).

What this IS NOT:
* Not live traffic -- nothing is actually routed or served.
* Not a health gate -- switch() does not validate the version.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

#: Module version.
TOOL_SYSTEM_22_VERSION = "tool-system-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-22.v1"


class ToolSystem22Error(Exception):
    """Fail-closed."""


@dataclass
class _SwitchEvent:
    from_slot: str
    to_slot: str
    version: str
    ts: float


class BlueGreenDeploy:
    """Two-slot blue/green deploy router (Simulated)."""

    SLOTS = ("blue", "green")

    def __init__(
        self,
        tool: str,
        initial_version: str,
        active: str = "blue",
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not tool:
            raise ToolSystem22Error("tool required")
        if not initial_version:
            raise ToolSystem22Error("initial_version required")
        if active not in self.SLOTS:
            raise ToolSystem22Error(f"active must be one of {self.SLOTS}")
        self.tool = tool
        self._slots: Dict[str, Optional[str]] = {
            "blue": None,
            "green": None,
        }
        self._slots[active] = initial_version
        self._active = active
        self._clock = clock or time.time
        self._history: List[_SwitchEvent] = []

    def active_slot(self) -> str:
        return self._active

    def inactive_slot(self) -> str:
        return "green" if self._active == "blue" else "blue"

    def deploy_to_inactive(self, version: str) -> None:
        """Stage a version in the inactive slot."""
        if not version:
            raise ToolSystem22Error("version required")
        self._slots[self.inactive_slot()] = version

    def switch(self) -> str:
        """Swap the active slot; returns the new active version."""
        target = self.inactive_slot()
        version = self._slots[target]
        if version is None:
            raise ToolSystem22Error(
                f"inactive slot '{target}' has no version"
            )
        ts = self._clock()
        self._history.append(
            _SwitchEvent(self._active, target, version, ts)
        )
        self._active = target
        return version

    def route(self) -> str:
        """Return the currently active version."""
        version = self._slots[self._active]
        if version is None:
            raise ToolSystem22Error("active slot has no version")
        return version

    def history(self) -> List[Dict[str, object]]:
        return [
            {
                "from_slot": e.from_slot,
                "to_slot": e.to_slot,
                "version": e.version,
                "ts": e.ts,
            }
            for e in self._history
        ]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
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
    now = {"t": 1000.0}
    bg = BlueGreenDeploy(
        "search", "v1", active="blue", clock=lambda: now["t"]
    )
    assert bg.route() == "v1"
    assert bg.active_slot() == "blue"
    assert bg.inactive_slot() == "green"
    # Cannot switch to an empty inactive slot.
    try:
        bg.switch()
        raise AssertionError("should raise")
    except ToolSystem22Error:
        pass
    bg.deploy_to_inactive("v2")
    now["t"] = 1001.0
    assert bg.switch() == "v2"
    assert bg.route() == "v2"
    assert bg.active_slot() == "green"
    hist = bg.history()
    assert len(hist) == 1
    assert hist[0] == {
        "from_slot": "blue",
        "to_slot": "green",
        "version": "v2",
        "ts": 1001.0,
    }
    # Switch back to v1 still staged in blue.
    now["t"] = 1002.0
    assert bg.switch() == "v1"
    assert bg.route() == "v1"
    assert len(bg.history()) == 2
    # Bad config.
    try:
        BlueGreenDeploy("t", "", active="blue")
        raise AssertionError("should raise")
    except ToolSystem22Error:
        pass
    try:
        BlueGreenDeploy("t", "v1", active="red")
        raise AssertionError("should raise")
    except ToolSystem22Error:
        pass
    assert stdlib_only()
    print("tool_system_22 OK: slots, switch, history")


if __name__ == "__main__":
    main()
