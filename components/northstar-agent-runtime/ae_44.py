"""AE-module: count_occurrences -- Times v appears in xs."""
from __future__ import annotations
VERSION = "ae_44.v1"
def count_occurrences(xs: list, v) -> int:
    return xs.count(v)

def main() -> None:
    assert count_occurrences([1, 2, 1, 1], 1) == 3
    assert count_occurrences([], 5) == 0
    assert count_occurrences([1, 2, 3], 9) == 0
    print("ae_44 count_occurrences OK")
if __name__ == "__main__": main()
