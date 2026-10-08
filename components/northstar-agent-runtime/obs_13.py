"""obs_13: Profiling (cProfile wrapper), Simulated.

Runs a callable under cProfile and returns the top-N function stats
as plain data (no pstats file I/O).

Fail-closed: fn must be callable.
Stdlib only (cProfile, pstats, io).
"""

from __future__ import annotations

import ast
import cProfile
import io
import pstats
from typing import Any, Callable, Dict, List

OBS13_VERSION = "obs-13.v1"
SCHEMA_PIN = "northstar.obs-13.v1"


class Obs13Error(Exception):
    """Fail-closed."""


def profile(
    fn: Callable[..., Any],
    *args: Any,
    top_n: int = 10,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Profile fn(*args, **kwargs).  Returns result + top-N stats."""
    if not callable(fn):
        raise Obs13Error("fn must be callable")
    if not isinstance(top_n, int) or top_n < 1:
        raise Obs13Error("top_n must be positive int")
    pr = cProfile.Profile()
    pr.enable()
    try:
        result = fn(*args, **kwargs)
    finally:
        pr.disable()
    buf = io.StringIO()
    ps = pstats.Stats(pr, stream=buf)
    ps.sort_stats("cumulative")
    # Extract top-N as data.
    stats: List[Dict[str, Any]] = []
    for func, stat in list(ps.stats.items())[:top_n]:
        # stat: (cc, nc, tt, ct, callers)
        stats.append({
            "func": f"{func[0]}:{func[1]}:{func[2]}",
            "calls": stat[1],
            "tottime": stat[2],
            "cumtime": stat[3],
        })
    return {"result": result, "top": stats, "top_n": top_n}


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "cProfile", "io", "pathlib", "pstats", "typing"}
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
    def work(n: int) -> int:
        return sum(range(n))

    out = profile(work, 1000, top_n=5)
    assert out["result"] == sum(range(1000))
    assert len(out["top"]) <= 5
    assert all("cumtime" in s for s in out["top"])
    try:
        profile("not-callable")  # type: ignore
        raise AssertionError("should raise")
    except Obs13Error:
        pass
    assert stdlib_only()
    print("obs_13 OK")


if __name__ == "__main__":
    main()
