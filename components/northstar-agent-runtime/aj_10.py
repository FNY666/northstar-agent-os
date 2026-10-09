"""AJ-10: Prefix sums."""
from __future__ import annotations
VERSION = "aj_10.v1"


def prefix_sums(seq):
    out, s = [], 0
    for x in seq: s += x; out.append(s)
    return out

def main() -> None:
    assert prefix_sums([1,2,3]) == [1,3,6]
    assert prefix_sums([]) == []
    print(f"aj_10 OK")
if __name__ == "__main__": main()
