"""Runtime defense 20: Process limits, Simulated.

Cap on child processes spawned per task.  Fork bombs and runaway
parallelism die here.

What this IS: spawn-budget config + accounting.

What this IS NOT:
* Not the spawner -- host enforces at fork/exec time.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

#: Module version.
RUNTIME_DEFENSE_20_VERSION = "runtime-defense-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-20.v1"


class ProcessLimitError(Exception):
    """Fail-closed: bad limits or over-budget spawns raise."""


@dataclass(frozen=True)
class ProcessLimits:
    """Process spawn limits."""

    max_processes: int = 16
    max_depth: int = 3  # process tree depth

    def __post_init__(self):
        if self.max_processes <= 0:
            raise ProcessLimitError("max_processes must be positive")
        if self.max_depth <= 0:
            raise ProcessLimitError("max_depth must be positive")


@dataclass
class SpawnLedger:
    """Tracks spawned processes."""

    spawned: int = 0

    def spawn(self, limits: ProcessLimits, depth: int = 1) -> None:
        """Record a spawn; raise if over budget or too deep."""
        if depth > limits.max_depth:
            raise ProcessLimitError(
                f"depth {depth} > max {limits.max_depth}"
            )
        if self.spawned >= limits.max_processes:
            raise ProcessLimitError(
                f"process budget exhausted: {limits.max_processes}"
            )
        self.spawned += 1


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib"}
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
    limits = ProcessLimits(max_processes=2, max_depth=2)
    ledger = SpawnLedger()
    ledger.spawn(limits, depth=1)
    ledger.spawn(limits, depth=2)
    assert ledger.spawned == 2
    try:
        ledger.spawn(limits, depth=1)  # budget exhausted
        raise AssertionError("should raise")
    except ProcessLimitError:
        pass
    try:
        SpawnLedger().spawn(limits, depth=5)  # too deep
        raise AssertionError("should raise")
    except ProcessLimitError:
        pass
    try:
        ProcessLimits(max_processes=0)
        raise AssertionError("should raise")
    except ProcessLimitError:
        pass
    assert stdlib_only()
    print("runtime-defense-20 OK: process limits, accounting, fail-closed")


if __name__ == "__main__":
    main()
