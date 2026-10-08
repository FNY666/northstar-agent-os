"""Minimum Number of Refueling Stops: fewest refuel stops to reach a target distance IS: max-heap of fuel available at passed stations IS NOT: dynamic programming over stations"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-17.v1"

def _req_inputs(target, start_fuel, stations):
    for name, v in (("target", target), ("start_fuel", start_fuel)):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            raise ValueError(f"{name} must be a non-negative number")
    if not isinstance(stations, list):
        raise ValueError("stations must be a list")
    out = []
    for i, st in enumerate(stations):
        if (not isinstance(st, (list, tuple)) or len(st) != 2
                or any(isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0 for v in st)):
            raise ValueError(f"stations[{i}] must be a non-negative numeric pair")
        out.append((st[0], st[1]))
    return target, start_fuel, out


def min_refuel_stops(target, start_fuel, stations):
    """Return the minimum refuel stops, or -1 if unreachable.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    target, start_fuel, stations = _req_inputs(target, start_fuel, stations)
    stations.sort()
    heap = []
    i = 0
    fuel = start_fuel
    stops = 0
    while fuel < target:
        while i < len(stations) and stations[i][0] <= fuel:
            heapq.heappush(heap, -stations[i][1])
            i += 1
        if not heap:
            return -1
        fuel += -heapq.heappop(heap)
        stops += 1
    return stops

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert min_refuel_stops(100, 10, [[10, 60], [20, 30], [30, 30], [60, 40]]) == 2
    assert min_refuel_stops(1, 1, []) == 0
    assert min_refuel_stops(100, 1, [[10, 100]]) == -1
    assert min_refuel_stops(10, 10, []) == 0
    try:
        min_refuel_stops(-1, 1, [])
    except ValueError:
        pass
    else:
        raise AssertionError("negative target must raise ValueError")
    assert stdlib_only()
    print("heap-17.v1 OK")


if __name__ == "__main__":
    main()
