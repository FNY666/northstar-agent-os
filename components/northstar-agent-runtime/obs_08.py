"""obs_08: Trace tail sampling, Simulated.

Decides whether to keep a completed trace based on its content:
keep if it has errors or is slow.  Otherwise drop.

This is "tail" sampling: the decision happens after the trace
completes, unlike head sampling (decide at start).

Fail-closed: invalid trace raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List

OBS08_VERSION = "obs-08.v1"
SCHEMA_PIN = "northstar.obs-08.v1"


class Obs08Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class FinishedSpan:
    name: str
    duration_ms: float
    has_error: bool = False


def should_keep(
    spans: List[FinishedSpan],
    *,
    slow_threshold_ms: float = 1000.0,
) -> bool:
    """Keep the trace if any span errored or was slow."""
    if not isinstance(spans, list):
        raise Obs08Error("spans must be list")
    if slow_threshold_ms <= 0:
        raise Obs08Error("threshold must be positive")
    for s in spans:
        if not isinstance(s, FinishedSpan):
            raise Obs08Error("spans must be FinishedSpan")
        if s.has_error:
            return True
        if s.duration_ms >= slow_threshold_ms:
            return True
    return False


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    ok = [FinishedSpan("a", 10), FinishedSpan("b", 20)]
    assert should_keep(ok) is False  # all fast, no errors
    err = [FinishedSpan("a", 10, has_error=True)]
    assert should_keep(err) is True
    slow = [FinishedSpan("a", 5000)]
    assert should_keep(slow) is True
    try:
        should_keep("bad")  # type: ignore
        raise AssertionError("should raise")
    except Obs08Error:
        pass
    assert stdlib_only()
    print("obs_08 OK")


if __name__ == "__main__":
    main()
