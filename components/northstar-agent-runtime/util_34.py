"""Progress helpers: percent, text bar, ETA. What this IS: CLI progress math. What this IS NOT: not a live renderer."""

from __future__ import annotations

import ast


#: Module version.
UTIL_34_VERSION = "util-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-34.v1"


def percent(done: float, total: float) -> float:
    if total <= 0:
        return 0.0
    return done / total * 100


def bar(done: float, total: float, width=20) -> str:
    p = percent(done, total)
    filled = int(width * min(max(p, 0.0), 100.0) / 100)
    return f"[{'#' * filled}{'-' * (width - filled)}] {p:.0f}%"


def eta_seconds(elapsed: float, done: float, total: float):
    """Estimated seconds remaining, or None if unknown."""
    if done <= 0 or elapsed < 0:
        return None
    return elapsed / done * (total - done)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib']
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
    assert percent(1, 2) == 50.0
    assert percent(1, 0) == 0.0
    assert bar(1, 2, 10) == "[#####-----] 50%"
    assert bar(0, 4, 4) == "[----] 0%"
    assert eta_seconds(10.0, 1, 4) == 30.0
    assert eta_seconds(10.0, 0, 4) is None
    print("progress helpers OK")


if __name__ == "__main__":
    main()
