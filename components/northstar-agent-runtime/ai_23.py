"""Accuracy Util (AI-U-023), Simulated."""
from __future__ import annotations
VERSION = "ai_23.v1"

def accuracy(preds, labels):
    return sum(p == l for p, l in zip(preds, labels)) / len(labels)

def main() -> None:
    assert accuracy([1, 0, 1], [1, 0, 0]) == 2/3
    assert accuracy([1], [1]) == 1.0
    print(f"ai_23 OK")
if __name__ == "__main__": main()
