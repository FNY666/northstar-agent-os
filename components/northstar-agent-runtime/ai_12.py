"""Clamp Batch Util (AI-U-012), Simulated."""
from __future__ import annotations
VERSION = "ai_12.v1"

def clamp_all(xs, lo, hi):
    return [max(lo, min(hi, x)) for x in xs]

def main() -> None:
    assert clamp_all([-1, 5, 99], 0, 10) == [0, 5, 10]
    assert clamp_all([], 0, 1) == []
    print(f"ai_12 OK")
if __name__ == "__main__": main()
