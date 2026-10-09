"""EMA Util (AI-U-043), Simulated."""
from __future__ import annotations
VERSION = "ai_43.v1"

def ema(xs, alpha):
    v = xs[0]
    for x in xs[1:]:
        v = alpha * x + (1 - alpha) * v
    return v

def main() -> None:
    assert abs(ema([1, 2, 3], 0.5) - 2.25) < 1e-9
    assert ema([5], 0.3) == 5
    print(f"ai_43 OK")
if __name__ == "__main__": main()
