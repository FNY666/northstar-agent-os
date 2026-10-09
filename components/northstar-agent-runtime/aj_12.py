"""AJ-12: Median."""
from __future__ import annotations
VERSION = "aj_12.v1"


def median(seq):
    s = sorted(seq); n = len(s)
    return s[n//2] if n % 2 else (s[n//2-1] + s[n//2]) / 2

def main() -> None:
    assert median([3,1,2]) == 2
    assert median([1,2,3,4]) == 2.5
    print(f"aj_12 OK")
if __name__ == "__main__": main()
