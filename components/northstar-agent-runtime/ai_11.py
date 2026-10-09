"""Min-Max Scale Util (AI-U-011), Simulated."""
from __future__ import annotations
VERSION = "ai_11.v1"

def minmax(xs):
    lo, hi = min(xs), max(xs)
    return [(x - lo) / (hi - lo) for x in xs] if hi > lo else [0.0] * len(xs)

def main() -> None:
    assert minmax([2, 4, 6]) == [0.0, 0.5, 1.0]
    assert minmax([3, 3]) == [0.0, 0.0]
    print(f"ai_11 OK")
if __name__ == "__main__": main()
