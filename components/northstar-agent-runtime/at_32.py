"""at_32: mean -- Arithmetic mean."""
from __future__ import annotations
VERSION = "at_32.v1"
def mean(xs):
    return sum(xs) / len(xs) if xs else 0

def main() -> None:
    assert mean([1, 2, 3]) == 2.0
    assert mean([]) == 0
    print("at_32 mean OK")
if __name__ == "__main__": main()
