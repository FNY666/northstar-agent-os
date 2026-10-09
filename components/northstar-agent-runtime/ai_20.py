"""Precision Util (AI-U-020), Simulated."""
from __future__ import annotations
VERSION = "ai_20.v1"

def precision(tp, fp):
    return tp / (tp + fp) if tp + fp else 0.0

def main() -> None:
    assert abs(precision(3, 1) - 0.75) < 1e-9
    assert precision(0, 0) == 0.0
    print(f"ai_20 OK")
if __name__ == "__main__": main()
