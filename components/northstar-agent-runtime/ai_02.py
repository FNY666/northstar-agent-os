"""Sigmoid Util (AI-U-002), Simulated."""
from __future__ import annotations
VERSION = "ai_02.v1"

def sigmoid(x):
    import math
    return 1.0 / (1.0 + math.exp(-x))

def main() -> None:
    assert abs(sigmoid(0) - 0.5) < 1e-12
    assert sigmoid(100) > 0.999 and sigmoid(-100) < 0.001
    print(f"ai_02 OK")
if __name__ == "__main__": main()
