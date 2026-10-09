"""Token Budget Split Util (AI-U-039), Simulated."""
from __future__ import annotations
VERSION = "ai_39.v1"

def budget_split(total, weights):
    s = sum(weights)
    return [total * w / s for w in weights]

def main() -> None:
    assert budget_split(100, [1, 1, 2]) == [25.0, 25.0, 50.0]
    assert abs(sum(budget_split(10, [3, 7])) - 10) < 1e-9
    print(f"ai_39 OK")
if __name__ == "__main__": main()
