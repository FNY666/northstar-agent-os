"""Variance Util (AI-U-034), Simulated."""
from __future__ import annotations
VERSION = "ai_34.v1"

def variance(xs):
    m = sum(xs) / len(xs)
    return sum((x - m) ** 2 for x in xs) / len(xs)

def main() -> None:
    assert abs(variance([1, 2, 3]) - 2/3) < 1e-9
    assert variance([5, 5]) == 0.0
    print(f"ai_34 OK")
if __name__ == "__main__": main()
