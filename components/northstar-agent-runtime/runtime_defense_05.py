"""Runtime defense 05: cgroup limits (config), Simulated.

Cgroup v2 resource limit config: memory, CPU, pids.  The config renders
to cgroupfs file writes (e.g. memory.max, cpu.max, pids.max).  Actual
enforcement is done by the kernel cgroup controller.

What this IS: validated cgroup v2 limit config + file rendering.
What this IS NOT: actual cgroup creation/writes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict

#: Module version.
RUNTIME_DEFENSE_05_VERSION = "runtime-defense-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-05.v1"


class CgroupError(Exception):
    """Fail-closed: bad limits raise."""


def _parse_bytes(value: str) -> int:
    """Parse '512M', '2G', '1024' into bytes."""
    value = value.strip()
    units = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if value[-1].upper() in units and value[:-1].isdigit():
        return int(value[:-1]) * units[value[-1].upper()]
    if value.isdigit():
        return int(value)
    raise CgroupError(f"bad byte value {value!r}")


@dataclass(frozen=True)
class CgroupLimits:
    """Validated cgroup v2 limits."""

    memory_max: str = "512M"   # e.g. "512M", "max"
    cpu_max: str = "100000 100000"  # "$MAX $PERIOD" => 1 CPU
    pids_max: int = 128

    def __post_init__(self):
        if self.memory_max != "max":
            _parse_bytes(self.memory_max)  # validates
        parts = self.cpu_max.split()
        if self.cpu_max != "max" and not (
            len(parts) == 2 and all(p.isdigit() for p in parts)
        ):
            raise CgroupError(f"bad cpu.max {self.cpu_max!r}")
        if not isinstance(self.pids_max, int) or self.pids_max <= 0:
            raise CgroupError("pids_max must be positive int")

    def render(self) -> Dict[str, str]:
        """Render as cgroupfs file -> value mapping."""
        mem = "max" if self.memory_max == "max" else str(_parse_bytes(self.memory_max))
        return {
            "memory.max": mem,
            "cpu.max": self.cpu_max,
            "pids.max": str(self.pids_max),
        }

    def memory_bytes(self) -> int | None:
        """Memory limit in bytes, None for 'max'."""
        if self.memory_max == "max":
            return None
        return _parse_bytes(self.memory_max)


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
    lim = CgroupLimits()
    rendered = lim.render()
    assert rendered["memory.max"] == str(512 * 1024 ** 2)
    assert rendered["pids.max"] == "128"
    assert lim.memory_bytes() == 512 * 1024 ** 2

    custom = CgroupLimits(memory_max="2G", cpu_max="50000 100000", pids_max=64)
    assert custom.memory_bytes() == 2 * 1024 ** 3

    try:
        CgroupLimits(memory_max="bogus")
        raise AssertionError("should raise")
    except CgroupError:
        pass
    try:
        CgroupLimits(pids_max=0)
        raise AssertionError("should raise")
    except CgroupError:
        pass

    assert stdlib_only()
    print("runtime-defense-05 OK: cgroup limits, render, fail-closed, stdlib")


if __name__ == "__main__":
    main()
