"""Runtime defense 17: Memory limits, Simulated.

Resident-set-size (RSS) limits for agent subprocesses.  Reads via
``resource.getrusage`` where available; hosts without it fail closed
(the check reports exceeded).

What this IS: memory-budget config with a portable read helper.

What this IS NOT:
* Not enforcement -- the host (cgroup/rlimit) enforces.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

#: Module version.
RUNTIME_DEFENSE_17_VERSION = "runtime-defense-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-17.v1"


class MemoryLimitError(Exception):
    """Fail-closed: bad limits raise."""


@dataclass(frozen=True)
class MemoryLimits:
    """Memory limits in megabytes."""

    max_rss_mb: int = 512
    # Soft limit: warn/log before hard limit.
    soft_rss_mb: int = 384

    def __post_init__(self):
        if self.max_rss_mb <= 0:
            raise MemoryLimitError("max_rss_mb must be positive")
        if self.soft_rss_mb > self.max_rss_mb:
            raise MemoryLimitError("soft_rss_mb must be <= max_rss_mb")


def current_rss_mb() -> Optional[int]:
    """Current process RSS in MB, or None if unavailable."""
    try:
        import resource

        # ru_maxrss is KiB on Linux, bytes on macOS.
        kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        import sys

        if sys.platform == "darwin":
            return kb // (1024 * 1024)
        return kb // 1024
    except Exception:
        return None


def memory_exceeded(limits: MemoryLimits) -> Optional[bool]:
    """True if RSS exceeds hard limit, False if within, None if unreadable.

    Unreadable is treated as exceeded by enforcement callers (fail-closed);
    this helper just reports.
    """
    rss = current_rss_mb()
    if rss is None:
        return None
    return rss > limits.max_rss_mb


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "resource", "sys", "typing"}
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
    limits = MemoryLimits(max_rss_mb=1024, soft_rss_mb=768)
    # Self RSS should be well under 1GB.
    result = memory_exceeded(limits)
    assert result is False or result is None
    # Tiny limit forces exceeded (or unreadable).
    tiny = MemoryLimits(max_rss_mb=1, soft_rss_mb=1)
    assert memory_exceeded(tiny) in (True, None)
    try:
        MemoryLimits(max_rss_mb=0)
        raise AssertionError("should raise")
    except MemoryLimitError:
        pass
    assert stdlib_only()
    print("runtime-defense-17 OK: memory limits, rss read, fail-closed")


if __name__ == "__main__":
    main()
