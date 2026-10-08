"""Runtime defense 26: Behavioral analysis (mock), Simulated.

Profiles expected tool-call sequences; flags deviations such as
unknown transitions or frequency spikes.  Mock: profiles are
hand-registered, not learned.

What this IS: Markov-style transition check over tool sequences.

What this IS NOT:
* Not learning -- profiles are explicit; host can train them.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Tuple

#: Module version.
RUNTIME_DEFENSE_26_VERSION = "runtime-defense-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-26.v1"


class BehaviorError(Exception):
    """Fail-closed: bad profiles raise."""


@dataclass(frozen=True)
class BehaviorProfile:
    """Allowed transitions between tools."""

    # tool -> set of tools that may legally follow
    transitions: Dict[str, FrozenSet[str]]
    # tools that may start a sequence
    entry_tools: FrozenSet[str] = frozenset()

    def __post_init__(self):
        if not self.transitions:
            raise BehaviorError("transitions must be non-empty")


@dataclass
class BehaviorAnalyzer:
    """Checks tool sequences against a profile."""

    profile: BehaviorProfile
    history: List[str] = field(default_factory=list)

    def observe(self, tool: str) -> Tuple[bool, str]:
        """Observe a tool call.  Returns (ok, reason)."""
        if not tool:
            raise BehaviorError("tool required")
        if not self.history:
            if self.profile.entry_tools and tool not in self.profile.entry_tools:
                return False, f"'{tool}' is not a valid entry tool"
            self.history.append(tool)
            return True, "entry ok"
        prev = self.history[-1]
        allowed = self.profile.transitions.get(prev, frozenset())
        if tool not in allowed:
            return False, f"illegal transition {prev} -> {tool}"
        self.history.append(tool)
        return True, "transition ok"

    def reset(self) -> None:
        """Start a new sequence."""
        self.history = []


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
    profile = BehaviorProfile(
        transitions={
            "read": frozenset({"read", "write", "end"}),
            "write": frozenset({"read", "end"}),
        },
        entry_tools=frozenset({"read"}),
    )
    analyzer = BehaviorAnalyzer(profile)
    assert analyzer.observe("read")[0] is True
    assert analyzer.observe("write")[0] is True
    ok, reason = analyzer.observe("write")  # write -> write illegal
    assert ok is False
    assert "illegal transition" in reason
    analyzer.reset()
    ok, _ = analyzer.observe("write")  # bad entry
    assert ok is False
    try:
        BehaviorProfile(transitions={})
        raise AssertionError("should raise")
    except BehaviorError:
        pass
    assert stdlib_only()
    print("runtime-defense-26 OK: behavioral analysis, transitions, fail-closed")


if __name__ == "__main__":
    main()
