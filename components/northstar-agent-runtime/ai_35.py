"""Std Dev Util (AI-U-035), Simulated."""
from __future__ import annotations
VERSION = "ai_35.v1"

def stdev(xs):
    import math
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))

def main() -> None:
    assert abs(stdev([1, 2, 3]) - 0.8164965809) < 1e-6
    assert stdev([5, 5]) == 0.0
    print(f"ai_35 OK")
if __name__ == "__main__": main()
