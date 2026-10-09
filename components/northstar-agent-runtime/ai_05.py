"""Cosine Similarity Util (AI-U-005), Simulated."""
from __future__ import annotations
VERSION = "ai_05.v1"

def cosine_sim(a, b):
    import math
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0

def main() -> None:
    assert abs(cosine_sim([1, 0], [0, 1])) < 1e-9
    assert abs(cosine_sim([1, 1], [1, 1]) - 1.0) < 1e-9
    print(f"ai_05 OK")
if __name__ == "__main__": main()
