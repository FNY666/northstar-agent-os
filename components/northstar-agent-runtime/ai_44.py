"""Sliding Window Util (AI-U-044), Simulated."""
from __future__ import annotations
VERSION = "ai_44.v1"

def windows(xs, w, step=1):
    return [xs[i:i + w] for i in range(0, len(xs) - w + 1, step)]

def main() -> None:
    assert windows([1, 2, 3, 4], 2) == [[1, 2], [2, 3], [3, 4]]
    assert windows([1, 2], 2, 5) == [[1, 2]]
    print(f"ai_44 OK")
if __name__ == "__main__": main()
