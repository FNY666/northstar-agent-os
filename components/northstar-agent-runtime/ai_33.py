"""Median Util (AI-U-033), Simulated."""
from __future__ import annotations
VERSION = "ai_33.v1"

def median(xs):
    s = sorted(xs)
    n = len(s)
    return (s[n // 2] + s[(n - 1) // 2]) / 2

def main() -> None:
    assert median([1, 2, 3]) == 2
    assert median([1, 2, 3, 4]) == 2.5
    print(f"ai_33 OK")
if __name__ == "__main__": main()
