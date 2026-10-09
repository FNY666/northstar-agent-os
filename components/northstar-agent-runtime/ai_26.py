"""Linear Predict Util (AI-U-026), Simulated."""
from __future__ import annotations
VERSION = "ai_26.v1"

def linear(xs, weights, bias=0.0):
    return sum(x * w for x, w in zip(xs, weights)) + bias

def main() -> None:
    assert linear([1, 2], [3, 4]) == 11
    assert linear([1], [2], 5) == 7
    print(f"ai_26 OK")
if __name__ == "__main__": main()
