"""Runtime defense 18: CPU limits, Simulated.

CPU-time limits (user+system) per action.  Reads via ``resource`` /
``time.process_time``.  Exceeding is a halt, not a throttle.

What this IS: cpu-budget config with a portable read helper.

What this IS NOT:
* Not enforcement -- host (rlimit/cpu cgroup) enforces.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

#: Module version.
RUNTIME_DEFENSE_18_VERSION = "runtime-defense-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-18.v1"


class CpuLimitError(Exception):
    """Fail-closed: bad limits raise."""


@dataclass(frozen=True)
class CpuLimits:
    """CPU time limits in seconds."""

    max_cpu_seconds: float = 120.0
    soft_cpu_seconds: float = 90.0

    def __post_init__(self):
        if self.max_cpu_seconds <= 0:
            raise CpuLimitError("max_cpu_seconds must be positive")
        if self.soft_cpu_seconds > self.max_cpu_seconds:
            raise CpuLimitError("soft_cpu_seconds must be <= max_cpu_seconds")


def current_cpu_seconds() -> float:
    """Current process CPU time (user+system) in seconds."""
    import time

    return time.process_time()


def cpu_exceeded(elapsed_cpu: float, limits: CpuLimits) -> bool:
    """True if elapsed CPU exceeds the hard limit."""
    if elapsed_cpu < 0:
        raise CpuLimitError("elapsed_cpu must be >= 0")
    return elapsed_cpu > limits.max_cpu_seconds


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
    limits = CpuLimits(max_cpu_seconds=60.0, soft_cpu_seconds=30.0)
    assert cpu_exceeded(current_cpu_seconds(), limits) is False
    assert cpu_exceeded(61.0, limits) is True
    assert cpu_exceeded(30.0, limits) is False
    try:
        CpuLimits(max_cpu_seconds=0)
        raise AssertionError("should raise")
    except CpuLimitError:
        pass
    assert stdlib_only()
    print("runtime-defense-18 OK: cpu limits, read, fail-closed")


if __name__ == "__main__":
    main()
