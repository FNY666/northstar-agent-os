"""F1 Score Util (AI-U-022), Simulated."""
from __future__ import annotations
VERSION = "ai_22.v1"

def f1(prec, rec):
    return 2 * prec * rec / (prec + rec) if prec + rec else 0.0

def main() -> None:
    assert abs(f1(1.0, 1.0) - 1.0) < 1e-9
    assert f1(0.0, 0.0) == 0.0
    print(f"ai_22 OK")
if __name__ == "__main__": main()
