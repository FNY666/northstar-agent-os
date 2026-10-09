"""Percentile Util (AI-U-032), Simulated."""
from __future__ import annotations
VERSION = "ai_32.v1"

def percentile(xs, q):
    s = sorted(xs)
    k = (len(s) - 1) * q / 100
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)

def main() -> None:
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([7], 99) == 7
    print(f"ai_32 OK")
if __name__ == "__main__": main()
