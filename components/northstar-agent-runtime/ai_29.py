"""BCE Loss Util (AI-U-029), Simulated."""
from __future__ import annotations
VERSION = "ai_29.v1"

def bce(preds, targets):
    import math
    eps = 1e-12
    return -sum(t * math.log(p + eps) + (1 - t) * math.log(1 - p + eps) for p, t in zip(preds, targets)) / len(targets)

def main() -> None:
    assert bce([0.999], [1]) < 0.01
    assert abs(bce([0.5], [1]) - 0.6931) < 0.001
    print(f"ai_29 OK")
if __name__ == "__main__": main()
