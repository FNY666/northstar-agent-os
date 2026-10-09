"""Manhattan Distance Util (AI-U-014), Simulated."""
from __future__ import annotations
VERSION = "ai_14.v1"

def manhattan(a, b):
    return sum(abs(x - y) for x, y in zip(a, b))

def main() -> None:
    assert manhattan([0, 0], [3, 4]) == 7
    assert manhattan([1, 2], [1, 2]) == 0
    print(f"ai_14 OK")
if __name__ == "__main__": main()
