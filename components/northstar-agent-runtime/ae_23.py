"""AE-module: take -- First n elements of a list."""
from __future__ import annotations
VERSION = "ae_23.v1"
def take(xs: list, n: int) -> list:
    return xs[:n]

def main() -> None:
    assert take([1, 2, 3], 2) == [1, 2]
    assert take([1], 5) == [1]
    assert take([], 3) == []
    print("ae_23 take OK")
if __name__ == "__main__": main()
