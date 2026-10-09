"""Flatten Util (AI-U-045), Simulated."""
from __future__ import annotations
VERSION = "ai_45.v1"

def flatten(nested):
    out = []
    for x in nested:
        out.extend(flatten(x) if isinstance(x, list) else [x])
    return out

def main() -> None:
    assert flatten([1, [2, [3]], 4]) == [1, 2, 3, 4]
    assert flatten([]) == []
    print(f"ai_45 OK")
if __name__ == "__main__": main()
