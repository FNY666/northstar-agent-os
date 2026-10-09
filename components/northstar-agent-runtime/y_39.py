"""Y-module: count_occurrences -- Count occurrences of x in list."""
from __future__ import annotations
VERSION = "y_39.v1"
def count_occurrences(xs: list, x) -> int:
    return sum(1 for v in xs if v == x)

def main() -> None:
    assert count_occurrences([1, 2, 1], 1) == 2
    assert count_occurrences([], 1) == 0
    print("y_39 count_occurrences OK")
if __name__ == "__main__": main()
