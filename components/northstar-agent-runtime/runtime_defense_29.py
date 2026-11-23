"""Runtime defense 29: Bulkheads, Simulated.

Partitioned resource pools: each partition has its own capacity, so
one overloaded partition cannot starve the others.  Acquire/release
accounting with fail-closed on exhaustion.

What this IS: capacity partitioning config + accounting.

What this IS NOT:
* Not thread pools -- host maps partitions to executors.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict

#: Module version.
RUNTIME_DEFENSE_29_VERSION = "runtime-defense-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-29.v1"


class BulkheadError(Exception):
    """Fail-closed: bad config or exhausted partitions raise."""


@dataclass(frozen=True)
class BulkheadConfig:
    """Capacity per partition."""

    partitions: Dict[str, int]  # partition name -> capacity

    def __post_init__(self):
        if not self.partitions:
            raise BulkheadError("at least one partition required")
        for name, cap in self.partitions.items():
            if not name:
                raise BulkheadError("partition name required")
            if cap <= 0:
                raise BulkheadError(f"capacity for '{name}' must be positive")


@dataclass
class Bulkhead:
    """Partitioned capacity accounting."""

    config: BulkheadConfig
    used: Dict[str, int] = field(default_factory=dict)

    def acquire(self, partition: str) -> None:
        """Acquire one slot; raise if partition exhausted or unknown."""
        if partition not in self.config.partitions:
            raise BulkheadError(f"unknown partition '{partition}'")
        used = self.used.get(partition, 0)
        if used >= self.config.partitions[partition]:
            raise BulkheadError(f"partition '{partition}' exhausted")
        self.used[partition] = used + 1

    def release(self, partition: str) -> None:
        """Release one slot (never negative, never unknown)."""
        if partition not in self.config.partitions:
            raise BulkheadError(f"unknown partition '{partition}'")
        self.used[partition] = max(0, self.used.get(partition, 0) - 1)

    def available(self, partition: str) -> int:
        """Free slots in a partition."""
        if partition not in self.config.partitions:
            raise BulkheadError(f"unknown partition '{partition}'")
        return self.config.partitions[partition] - self.used.get(partition, 0)


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
    config = BulkheadConfig(partitions={"io": 2, "cpu": 1})
    bh = Bulkhead(config)
    bh.acquire("io")
    bh.acquire("io")
    assert bh.available("io") == 0
    try:
        bh.acquire("io")  # exhausted
        raise AssertionError("should raise")
    except BulkheadError:
        pass
    # Other partition unaffected.
    bh.acquire("cpu")
    assert bh.available("cpu") == 0
    bh.release("io")
    assert bh.available("io") == 1
    try:
        bh.acquire("nope")
        raise AssertionError("should raise")
    except BulkheadError:
        pass
    try:
        BulkheadConfig(partitions={})
        raise AssertionError("should raise")
    except BulkheadError:
        pass
    assert stdlib_only()
    print("runtime-defense-29 OK: bulkheads, partitioning, fail-closed")


if __name__ == "__main__":
    main()
