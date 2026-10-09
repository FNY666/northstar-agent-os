"""Y-module: mean -- Arithmetic mean of a non-empty list."""
from __future__ import annotations
VERSION = "y_17.v1"
def mean(xs: list) -> float:
    return sum(xs) / len(xs)

def main() -> None:
    assert mean([1, 2, 3]) == 2.0
    assert mean([5]) == 5.0
    print("y_17 mean OK")
if __name__ == "__main__": main()
