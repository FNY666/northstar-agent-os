"""Z-Score Util (AI-U-010), Simulated."""
from __future__ import annotations
VERSION = "ai_10.v1"

def zscore(xs):
    import statistics
    m, s = statistics.mean(xs), statistics.pstdev(xs)
    return [(x - m) / s for x in xs] if s else [0.0] * len(xs)

def main() -> None:
    import statistics
    assert abs(statistics.mean(zscore([1, 2, 3]))) < 1e-9
    assert zscore([7, 7]) == [0.0, 0.0]
    print(f"ai_10 OK")
if __name__ == "__main__": main()
