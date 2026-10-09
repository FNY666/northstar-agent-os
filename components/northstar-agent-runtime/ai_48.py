"""KL Divergence Util (AI-U-048), Simulated."""
from __future__ import annotations
VERSION = "ai_48.v1"

def kl(p, q):
    import math
    return sum(pi * math.log(pi / qi) for pi, qi in zip(p, q) if pi > 0)

def main() -> None:
    assert abs(kl([0.5, 0.5], [0.5, 0.5])) < 1e-12
    assert kl([1.0, 0.0], [0.5, 0.5]) > 0
    print(f"ai_48 OK")
if __name__ == "__main__": main()
