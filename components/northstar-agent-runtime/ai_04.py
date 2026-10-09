"""Vector Normalize Util (AI-U-004), Simulated."""
from __future__ import annotations
VERSION = "ai_04.v1"

def normalize(xs):
    import math
    n = math.sqrt(sum(x * x for x in xs))
    return [x / n for x in xs] if n else list(xs)

def main() -> None:
    import math
    assert abs(sum(x*x for x in normalize([3, 4])) - 1.0) < 1e-9
    assert normalize([0, 0]) == [0, 0]
    print(f"ai_04 OK")
if __name__ == "__main__": main()
