"""AF-module: percentile -- p-th percentile of values (0<=p<=100), linear interpolation."""
from __future__ import annotations
VERSION = "af_21"
def percentile(xs: list, p: float) -> float:
    if not xs:
        raise ValueError('empty')
    s = sorted(xs)
    k = (len(s) - 1) * min(100.0, max(0.0, p)) / 100.0
    lo, hi = int(k), min(len(s) - 1, int(k) + 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)

def main() -> None:
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([10], 99) == 10
    assert percentile([1, 2, 3, 4], 0) == 1
    print("af_21 percentile OK")
if __name__ == "__main__": main()
