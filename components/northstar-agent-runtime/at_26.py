"""at_26: dedup -- Remove duplicate items, keep order."""
from __future__ import annotations
VERSION = "at_26.v1"
def dedup(xs):
    seen = []
    return [x for x in xs if not (x in seen or seen.append(x))]

def main() -> None:
    assert dedup([1, 2, 1]) == [1, 2]
    assert dedup([]) == []
    print("at_26 dedup OK")
if __name__ == "__main__": main()
