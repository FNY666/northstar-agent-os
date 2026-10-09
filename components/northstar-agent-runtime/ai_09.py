"""Moving Average Util (AI-U-009), Simulated."""
from __future__ import annotations
VERSION = "ai_09.v1"

def moving_avg(xs, w):
    return [sum(xs[i:i + w]) / w for i in range(len(xs) - w + 1)]

def main() -> None:
    assert moving_avg([1, 2, 3, 4], 2) == [1.5, 2.5, 3.5]
    assert moving_avg([5], 1) == [5.0]
    print(f"ai_09 OK")
if __name__ == "__main__": main()
