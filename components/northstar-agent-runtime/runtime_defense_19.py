"""Runtime defense 19: Disk limits, Simulated.

Per-task disk-write quotas.  The host tracks bytes written; this module
holds the quota config and the accounting check.

What this IS: write-quota config + pure accounting helpers.

What this IS NOT:
* Not the byte counter -- host instruments writes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

#: Module version.
RUNTIME_DEFENSE_19_VERSION = "runtime-defense-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-19.v1"


class DiskLimitError(Exception):
    """Fail-closed: bad quotas raise."""


@dataclass(frozen=True)
class DiskLimits:
    """Disk write quotas in bytes."""

    max_write_bytes: int = 100 * 1024 * 1024  # 100 MiB
    max_single_write_bytes: int = 10 * 1024 * 1024  # 10 MiB

    def __post_init__(self):
        if self.max_write_bytes <= 0:
            raise DiskLimitError("max_write_bytes must be positive")
        if self.max_single_write_bytes <= 0:
            raise DiskLimitError("max_single_write_bytes must be positive")
        if self.max_single_write_bytes > self.max_write_bytes:
            raise DiskLimitError(
                "max_single_write_bytes must be <= max_write_bytes"
            )


@dataclass
class WriteLedger:
    """Tracks bytes written this task."""

    bytes_written: int = 0

    def record(self, nbytes: int, limits: DiskLimits) -> None:
        """Record a write; raise if it breaks the quota."""
        if nbytes < 0:
            raise DiskLimitError("nbytes must be >= 0")
        if nbytes > limits.max_single_write_bytes:
            raise DiskLimitError(
                f"single write {nbytes} > {limits.max_single_write_bytes}"
            )
        if self.bytes_written + nbytes > limits.max_write_bytes:
            raise DiskLimitError(
                f"quota exceeded: {self.bytes_written + nbytes} > "
                f"{limits.max_write_bytes}"
            )
        self.bytes_written += nbytes


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
    limits = DiskLimits(max_write_bytes=1000, max_single_write_bytes=600)
    ledger = WriteLedger()
    ledger.record(400, limits)
    ledger.record(500, limits)
    assert ledger.bytes_written == 900
    try:
        ledger.record(200, limits)  # 1100 > 1000
        raise AssertionError("should raise")
    except DiskLimitError:
        pass
    try:
        ledger.record(700, limits)  # single write too big
        raise AssertionError("should raise")
    except DiskLimitError:
        pass
    try:
        DiskLimits(max_write_bytes=0)
        raise AssertionError("should raise")
    except DiskLimitError:
        pass
    assert stdlib_only()
    print("runtime-defense-19 OK: disk quotas, accounting, fail-closed")


if __name__ == "__main__":
    main()
