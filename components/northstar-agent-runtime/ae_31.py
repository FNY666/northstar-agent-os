"""AE-module: median -- Middle value of a sorted non-empty list."""
from __future__ import annotations
VERSION = "ae_31.v1"
def median(xs: list) -> float:
    if not xs:
        raise ValueError('empty')
    s = sorted(xs)
    n = len(s)
    m = n // 2
    return float(s[m]) if n % 2 else (s[m - 1] + s[m]) / 2

def main() -> None:
    assert median([3, 1, 2]) == 2.0
    assert median([1, 2, 3, 4]) == 2.5
    assert median([9]) == 9.0
    print("ae_31 median OK")
if __name__ == "__main__": main()
