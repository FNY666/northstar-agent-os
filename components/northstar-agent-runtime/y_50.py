"""Y-module: running_total -- Cumulative sums."""
from __future__ import annotations
VERSION = "y_50.v1"
def running_total(xs: list) -> list:
    out, s = [], 0
    for x in xs: s += x; out.append(s)
    return out

def main() -> None:
    assert running_total([1, 2, 3]) == [1, 3, 6]
    assert running_total([]) == []
    print("y_50 running_total OK")
if __name__ == "__main__": main()
