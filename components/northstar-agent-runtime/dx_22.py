"""DX-22: Coverage UI (mock), Simulated.

Record covered lines per file against a declared total line count.
`percent(file)` returns 0-100; `uncovered(file)` returns the missing
lines sorted. Out-of-range lines and unknown files raise.

What this IS: explicit line-coverage bookkeeping for UI plumbing.
What this IS NOT: not measured by executing code.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set

#: Module version.
DX22_COVERAGE_VERSION = "dx-coverage.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-coverage.v1"


class CoverageError(Exception):
    """Fail-closed."""


class CoverageTracker:
    """Per-file covered-line bookkeeping."""

    def __init__(self) -> None:
        self._covered: Dict[str, Set[int]] = {}
        self._totals: Dict[str, int] = {}

    def record(self, file: str, covered: List[int], total_lines: int) -> None:
        if not file:
            raise CoverageError("file required")
        if total_lines < 1:
            raise CoverageError("total_lines must be >= 1")
        for line in covered:
            if line < 1 or line > total_lines:
                raise CoverageError(f"line {line} out of range 1..{total_lines}")
        self._covered[file] = set(covered)
        self._totals[file] = total_lines

    def percent(self, file: str) -> float:
        if file not in self._totals:
            raise CoverageError(f"no coverage recorded for '{file}'")
        return 100.0 * len(self._covered[file]) / self._totals[file]

    def uncovered(self, file: str) -> List[int]:
        if file not in self._totals:
            raise CoverageError(f"no coverage recorded for '{file}'")
        return sorted(
            set(range(1, self._totals[file] + 1)) - self._covered[file]
        )

    @property
    def files(self) -> List[str]:
        return sorted(self._totals)


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
    cov = CoverageTracker()
    cov.record("a.py", [1, 2, 3, 5], 5)
    assert cov.percent("a.py") == 80.0
    assert cov.uncovered("a.py") == [4]
    cov.record("b.py", [1], 1)
    assert cov.percent("b.py") == 100.0
    assert cov.uncovered("b.py") == []
    try:
        cov.record("c.py", [0], 5)
        raise AssertionError("should raise")
    except CoverageError:
        pass
    try:
        cov.percent("nope.py")
        raise AssertionError("should raise")
    except CoverageError:
        pass
    assert cov.files == ["a.py", "b.py"]
    assert stdlib_only()
    print("dx_22 OK: percent, uncovered, range/unknown validation")


if __name__ == "__main__":
    main()
