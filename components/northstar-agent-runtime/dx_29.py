"""DX-29: Migration tools (mock), Simulated.

Versioned migration registry. `pending(current)` returns registered
versions above current in ascending order; `apply(version)` marks a
migration applied and requires all lower versions applied first (no
gaps). Duplicate registration and unknown versions raise.

What this IS: gap-free ordered migration bookkeeping.
What this IS NOT: not executing real schema changes.
"""

from __future__ import annotations

import ast
from typing import Dict, List

#: Module version.
DX29_MIGRATE_VERSION = "dx-migrate.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-migrate.v1"


class MigrateError(Exception):
    """Fail-closed."""


class MigrationRegistry:
    """Ordered, gap-free migration registry."""

    def __init__(self) -> None:
        self._migrations: Dict[int, str] = {}
        self._applied: List[int] = []

    def register(self, version: int, name: str) -> None:
        if not isinstance(version, int) or version < 1:
            raise MigrateError("version must be a positive int")
        if not name or not name.strip():
            raise MigrateError("name required")
        if version in self._migrations:
            raise MigrateError(f"duplicate migration {version}")
        self._migrations[version] = name

    def pending(self, current: int) -> List[int]:
        if not isinstance(current, int) or current < 0:
            raise MigrateError("current must be a non-negative int")
        return sorted(
            v for v in self._migrations
            if v > current and v not in self._applied
        )

    def apply(self, version: int) -> None:
        if version not in self._migrations:
            raise MigrateError(f"unknown migration {version}")
        if version in self._applied:
            raise MigrateError(f"migration {version} already applied")
        missing = [v for v in self._migrations
                   if v < version and v not in self._applied]
        if missing:
            raise MigrateError(
                f"cannot apply {version}: missing lower migrations {sorted(missing)}"
            )
        self._applied.append(version)

    def applied(self) -> List[int]:
        return sorted(self._applied)

    @property
    def versions(self) -> List[int]:
        return sorted(self._migrations)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    reg = MigrationRegistry()
    reg.register(1, "init")
    reg.register(2, "add users")
    reg.register(3, "add index")
    assert reg.pending(0) == [1, 2, 3]
    try:
        reg.apply(2)  # gap: 1 missing
        raise AssertionError("should raise")
    except MigrateError:
        pass
    reg.apply(1)
    reg.apply(2)
    assert reg.pending(0) == [3]
    assert reg.applied() == [1, 2]
    try:
        reg.register(2, "dup")
        raise AssertionError("should raise")
    except MigrateError:
        pass
    try:
        reg.apply(99)
        raise AssertionError("should raise")
    except MigrateError:
        pass
    assert reg.versions == [1, 2, 3]
    assert stdlib_only()
    print("dx_29 OK: pending order, gap enforcement, dupe/unknown rejected")


if __name__ == "__main__":
    main()
