"""AF-module: zscores -- Standardize values to z-scores (population std)."""
from __future__ import annotations
VERSION = "af_22"
import statistics
def zscores(xs: list) -> list:
    if not xs:
        return []
    m = statistics.fmean(xs)
    sd = statistics.pstdev(xs) or 1.0
    return [(x - m) / sd for x in xs]

def main() -> None:
    assert zscores([1, 2, 3]) == [-1.224744871391589, 0.0, 1.224744871391589]
    assert zscores([]) == []
    assert zscores([5, 5, 5]) == [0.0, 0.0, 0.0]
    print("af_22 zscores OK")
if __name__ == "__main__": main()
