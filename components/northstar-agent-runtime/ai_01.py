"""Softmax Util (AI-U-001), Simulated."""
from __future__ import annotations
VERSION = "ai_01.v1"

def softmax(xs):
    import math
    m = max(xs)
    ex = [math.exp(x - m) for x in xs]
    s = sum(ex)
    return [e / s for e in ex]

def main() -> None:
    assert abs(sum(softmax([1, 2, 3])) - 1.0) < 1e-9
    assert softmax([5])[0] == 1.0
    print(f"ai_01 OK")
if __name__ == "__main__": main()
