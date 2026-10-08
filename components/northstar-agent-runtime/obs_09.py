"""obs_09: Metrics cardinality (limit label values), Simulated.

Bounds the number of distinct label values to prevent cardinality
explosion.  Excess values are dropped (counted as overflow).

Fail-closed: invalid inputs raise; overflow is dropped, not stored.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict, Set

OBS09_VERSION = "obs-09.v1"
SCHEMA_PIN = "northstar.obs-09.v1"


class Obs09Error(Exception):
    """Fail-closed."""


class CardinalityLimiter:
    """Limits distinct values per label name."""

    def __init__(self, max_values_per_label: int = 100) -> None:
        if not isinstance(max_values_per_label, int) or max_values_per_label < 1:
            raise Obs09Error("max must be positive int")
        self._max = max_values_per_label
        self._seen: Dict[str, Set[str]] = {}
        self._overflow_count: Dict[str, int] = {}

    def check(self, label: str, value: str) -> bool:
        """True if the value is allowed (within cardinality budget)."""
        if not isinstance(label, str) or not label:
            raise Obs09Error("label must be non-empty str")
        if not isinstance(value, str):
            raise Obs09Error("value must be str")
        seen = self._seen.setdefault(label, set())
        if value in seen:
            return True
        if len(seen) >= self._max:
            self._overflow_count[label] = self._overflow_count.get(label, 0) + 1
            return False  # drop
        seen.add(value)
        return True

    def overflow_count(self, label: str) -> int:
        return self._overflow_count.get(label, 0)


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
    lim = CardinalityLimiter(max_values_per_label=2)
    assert lim.check("path", "/a") is True
    assert lim.check("path", "/b") is True
    assert lim.check("path", "/c") is False  # dropped
    assert lim.overflow_count("path") == 1
    assert lim.check("path", "/a") is True  # already seen, allowed
    try:
        lim.check("", "v")
        raise AssertionError("should raise")
    except Obs09Error:
        pass
    assert stdlib_only()
    print("obs_09 OK")


if __name__ == "__main__":
    main()
