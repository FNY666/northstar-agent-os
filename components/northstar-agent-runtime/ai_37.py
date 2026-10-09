"""Correlation Util (AI-U-037), Simulated."""
from __future__ import annotations
VERSION = "ai_37.v1"

def correlation(a, b):
    import math
    ma, mb = sum(a) / len(a), sum(b) / len(b)
    sa = math.sqrt(sum((x - ma) ** 2 for x in a))
    sb = math.sqrt(sum((x - mb) ** 2 for x in b))
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (sa * sb) if sa and sb else 0.0

def main() -> None:
    assert abs(correlation([1, 2, 3], [2, 4, 6]) - 1.0) < 1e-9
    assert correlation([1, 1], [1, 2]) == 0.0
    print(f"ai_37 OK")
if __name__ == "__main__": main()
