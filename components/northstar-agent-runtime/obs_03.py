"""obs_03: Log sampling (sample 1/N), Simulated.

Deterministic counter-based sampler: keeps 1 out of every N.
Avoids randomness for testability.

Fail-closed: N must be positive int.
Stdlib only.
"""

from __future__ import annotations

import ast

OBS03_VERSION = "obs-03.v1"
SCHEMA_PIN = "northstar.obs-03.v1"


class Obs03Error(Exception):
    """Fail-closed."""


class Sampler:
    """Keep 1/N events (deterministic)."""

    def __init__(self, n: int) -> None:
        if not isinstance(n, int) or n < 1:
            raise Obs03Error("n must be positive int")
        self._n = n
        self._count = 0

    def should_sample(self) -> bool:
        """True for every Nth call (1-indexed)."""
        self._count += 1
        return self._count % self._n == 0

    @property
    def count(self) -> int:
        return self._count


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    s = Sampler(3)
    results = [s.should_sample() for _ in range(6)]
    assert results == [False, False, True, False, False, True]
    s1 = Sampler(1)
    assert s1.should_sample() is True  # 1/1 keeps all
    try:
        Sampler(0)
        raise AssertionError("should raise")
    except Obs03Error:
        pass
    assert stdlib_only()
    print("obs_03 OK")


if __name__ == "__main__":
    main()
