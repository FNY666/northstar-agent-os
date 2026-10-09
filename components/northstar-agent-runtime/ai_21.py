"""Recall Util (AI-U-021), Simulated."""
from __future__ import annotations
VERSION = "ai_21.v1"

def recall(tp, fn):
    return tp / (tp + fn) if tp + fn else 0.0

def main() -> None:
    assert abs(recall(3, 1) - 0.75) < 1e-9
    assert recall(0, 0) == 0.0
    print(f"ai_21 OK")
if __name__ == "__main__": main()
