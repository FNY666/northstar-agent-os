"""Argmax Util (AI-U-007), Simulated."""
from __future__ import annotations
VERSION = "ai_07.v1"

def argmax(xs):
    return max(range(len(xs)), key=lambda i: xs[i])

def main() -> None:
    assert argmax([1, 9, 3]) == 1
    assert argmax([-5]) == 0
    print(f"ai_07 OK")
if __name__ == "__main__": main()
