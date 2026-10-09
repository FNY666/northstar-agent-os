"""Jaccard Similarity Util (AI-U-018), Simulated."""
from __future__ import annotations
VERSION = "ai_18.v1"

def jaccard(a, b):
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb) if sa | sb else 1.0

def main() -> None:
    assert abs(jaccard([1, 2], [2, 3]) - 1/3) < 1e-9
    assert jaccard([], []) == 1.0
    print(f"ai_18 OK")
if __name__ == "__main__": main()
