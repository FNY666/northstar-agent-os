"""Histogram Util (AI-U-047), Simulated."""
from __future__ import annotations
VERSION = "ai_47.v1"

def histogram(xs, bins):
    lo, hi = min(xs), max(xs)
    counts = [0] * bins
    for x in xs:
        i = min(int((x - lo) / (hi - lo + 1e-12) * bins), bins - 1)
        counts[i] += 1
    return counts

def main() -> None:
    assert sum(histogram([1, 2, 3, 4], 2)) == 4
    assert histogram([5], 3) == [1, 0, 0]
    print(f"ai_47 OK")
if __name__ == "__main__": main()
