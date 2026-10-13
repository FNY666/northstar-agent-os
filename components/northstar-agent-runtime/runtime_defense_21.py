"""Runtime defense 21: File descriptor limits, Simulated.

Cap on open file descriptors per task.  FD exhaustion is a classic
DoS vector; close-the-loop accounting lives here.

What this IS: fd-budget config + accounting + portable rlimit read.

What this IS NOT:
* Not the opener -- host enforces at open() time.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional, Tuple

#: Module version.
RUNTIME_DEFENSE_21_VERSION = "runtime-defense-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-21.v1"


class FdLimitError(Exception):
    """Fail-closed: bad limits or over-budget opens raise."""


@dataclass(frozen=True)
class FdLimits:
    """File descriptor limits."""

    max_fds: int = 256

    def __post_init__(self):
        if self.max_fds <= 0:
            raise FdLimitError("max_fds must be positive")


def system_fd_limit() -> Optional[Tuple[int, int]]:
    """Process rlimit (soft, hard) for NOFILE, or None if unavailable."""
    try:
        import resource

        return resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        return None


@dataclass
class FdLedger:
    """Tracks open FDs."""

    open_count: int = 0

    def open(self, limits: FdLimits) -> None:
        """Record an open; raise if over budget."""
        if self.open_count >= limits.max_fds:
            raise FdLimitError(
                f"fd budget exhausted: {limits.max_fds}"
            )
        self.open_count += 1

    def close(self) -> None:
        """Record a close (never goes negative)."""
        self.open_count = max(0, self.open_count - 1)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "resource", "typing"}
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
    limits = FdLimits(max_fds=2)
    ledger = FdLedger()
    ledger.open(limits)
    ledger.open(limits)
    assert ledger.open_count == 2
    try:
        ledger.open(limits)
        raise AssertionError("should raise")
    except FdLimitError:
        pass
    ledger.close()
    ledger.open(limits)  # slot freed
    assert ledger.open_count == 2
    rlim = system_fd_limit()
    assert rlim is None or (rlim[0] > 0 and rlim[1] >= rlim[0])
    try:
        FdLimits(max_fds=0)
        raise AssertionError("should raise")
    except FdLimitError:
        pass
    assert stdlib_only()
    print("runtime-defense-21 OK: fd limits, accounting, fail-closed")


if __name__ == "__main__":
    main()
