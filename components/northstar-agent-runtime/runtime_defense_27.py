"""Runtime defense 27: Kill switches, Simulated.

Named, scoped kill switches.  Tripping a switch immediately revokes
the run/session/task it covers.  Switches are append-only: once
tripped they stay tripped (no silent re-arm).

What this IS: scoped, one-way revocation.

What this IS NOT:
* Not the revocation transport -- host invalidates tokens/handles.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
RUNTIME_DEFENSE_27_VERSION = "runtime-defense-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-27.v1"


class KillSwitchError(Exception):
    """Fail-closed: unknown scopes raise."""


@dataclass
class KillSwitch:
    """One named kill switch."""

    name: str
    scope: str  # e.g. "task", "session", "run", "global"
    tripped: bool = False
    reason: str = ""

    def trip(self, reason: str) -> None:
        """Trip the switch (one-way)."""
        if not reason:
            raise KillSwitchError("trip reason required")
        self.tripped = True
        self.reason = reason


@dataclass
class KillSwitchBoard:
    """Registry of kill switches."""

    switches: Dict[str, KillSwitch] = field(default_factory=dict)

    def arm(self, name: str, scope: str) -> KillSwitch:
        """Arm a new switch."""
        if not name:
            raise KillSwitchError("name required")
        if name in self.switches:
            raise KillSwitchError(f"switch '{name}' already armed")
        switch = KillSwitch(name=name, scope=scope)
        self.switches[name] = switch
        return switch

    def trip(self, name: str, reason: str) -> None:
        """Trip a switch by name."""
        if name not in self.switches:
            raise KillSwitchError(f"unknown switch '{name}'")
        self.switches[name].trip(reason)

    def is_dead(self, scope: str) -> bool:
        """True if any switch covering the scope (or global) is tripped."""
        for switch in self.switches.values():
            if switch.tripped and switch.scope in (scope, "global"):
                return True
        return False

    def tripped_names(self) -> List[str]:
        """Names of tripped switches."""
        return [s.name for s in self.switches.values() if s.tripped]


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
    board = KillSwitchBoard()
    board.arm("task-kill", "task")
    board.arm("global-kill", "global")
    assert board.is_dead("task") is False
    board.trip("task-kill", "operator request")
    assert board.is_dead("task") is True
    assert board.is_dead("session") is False  # task scope != session
    board.trip("global-kill", "incident")
    assert board.is_dead("session") is True  # global covers all
    assert board.tripped_names() == ["task-kill", "global-kill"]
    try:
        board.trip("nope", "x")
        raise AssertionError("should raise")
    except KillSwitchError:
        pass
    assert stdlib_only()
    print("runtime-defense-27 OK: kill switches, scoping, fail-closed")


if __name__ == "__main__":
    main()
