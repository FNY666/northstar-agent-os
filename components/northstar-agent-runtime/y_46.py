"""Y-module: is_sorted_asc -- Check non-decreasing order."""
from __future__ import annotations
VERSION = "y_46.v1"
def is_sorted_asc(xs: list) -> bool:
    return all(xs[i] <= xs[i+1] for i in range(len(xs)-1))

def main() -> None:
    assert is_sorted_asc([1, 2, 2, 5]) is True
    assert is_sorted_asc([3, 1]) is False
    print("y_46 is_sorted_asc OK")
if __name__ == "__main__": main()
