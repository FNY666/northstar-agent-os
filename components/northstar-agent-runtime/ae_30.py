"""AE-module: mean -- Arithmetic mean of a non-empty list."""
from __future__ import annotations
VERSION = "ae_30.v1"
def mean(xs: list) -> float:
    if not xs:
        raise ValueError('empty')
    return sum(xs) / len(xs)

def main() -> None:
    assert mean([1, 2, 3]) == 2.0
    assert mean([5]) == 5.0
    assert mean([1.5, 2.5]) == 2.0
    print("ae_30 mean OK")
if __name__ == "__main__": main()
