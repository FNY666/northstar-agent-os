"""Covariance Util (AI-U-036), Simulated."""
from __future__ import annotations
VERSION = "ai_36.v1"

def covariance(a, b):
    ma, mb = sum(a) / len(a), sum(b) / len(b)
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / len(a)

def main() -> None:
    assert abs(covariance([1, 2, 3], [1, 2, 3]) - 2/3) < 1e-9
    assert covariance([5, 5], [1, 2]) == 0.0
    print(f"ai_36 OK")
if __name__ == "__main__": main()
