"""Dot Product Util (AI-U-030), Simulated."""
from __future__ import annotations
VERSION = "ai_30.v1"

def dot(a, b):
    return sum(x * y for x, y in zip(a, b))

def main() -> None:
    assert dot([1, 2], [3, 4]) == 11
    assert dot([], []) == 0
    print(f"ai_30 OK")
if __name__ == "__main__": main()
