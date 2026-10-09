"""AJ-13: Variance."""
from __future__ import annotations
VERSION = "aj_13.v1"


def variance(seq):
    m = sum(seq) / len(seq)
    return sum((x-m)**2 for x in seq) / len(seq)

def main() -> None:
    assert abs(variance([1,2,3,4]) - 1.25) < 1e-9
    assert variance([7,7,7]) == 0.0
    print(f"aj_13 OK")
if __name__ == "__main__": main()
