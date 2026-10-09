"""AJ-04: Dedup preserve order."""
from __future__ import annotations
VERSION = "aj_04.v1"


def dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen: seen.add(x); out.append(x)
    return out

def main() -> None:
    assert dedup([3,1,3,2,1]) == [3,1,2]
    assert dedup([]) == []
    print(f"aj_04 OK")
if __name__ == "__main__": main()
