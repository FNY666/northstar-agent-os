"""Euclidean Distance Util (AI-U-013), Simulated."""
from __future__ import annotations
VERSION = "ai_13.v1"

def euclid(a, b):
    import math
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

def main() -> None:
    assert abs(euclid([0, 0], [3, 4]) - 5.0) < 1e-9
    assert euclid([1], [1]) == 0.0
    print(f"ai_13 OK")
if __name__ == "__main__": main()
