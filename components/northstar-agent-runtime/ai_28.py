"""MSE Loss Util (AI-U-028), Simulated."""
from __future__ import annotations
VERSION = "ai_28.v1"

def mse(preds, targets):
    return sum((p - t) ** 2 for p, t in zip(preds, targets)) / len(targets)

def main() -> None:
    assert mse([1, 2], [1, 2]) == 0.0
    assert abs(mse([0, 0], [1, 1]) - 1.0) < 1e-9
    print(f"ai_28 OK")
if __name__ == "__main__": main()
