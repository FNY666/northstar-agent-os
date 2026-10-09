"""Entropy Util (AI-U-006), Simulated."""
from __future__ import annotations
VERSION = "ai_06.v1"

def entropy(ps):
    import math
    return -sum(p * math.log2(p) for p in ps if p > 0)

def main() -> None:
    assert abs(entropy([0.5, 0.5]) - 1.0) < 1e-9
    assert entropy([1.0, 0.0]) == 0.0
    print(f"ai_06 OK")
if __name__ == "__main__": main()
