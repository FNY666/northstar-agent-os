"""AE-module: dot_product -- Sum of pairwise products of two lists."""
from __future__ import annotations
VERSION = "ae_34.v1"
def dot_product(a: list, b: list) -> float:
    return sum(x * y for x, y in zip(a, b))

def main() -> None:
    assert dot_product([1, 2, 3], [4, 5, 6]) == 32
    assert dot_product([], []) == 0
    assert dot_product([1], [2]) == 2
    print("ae_34 dot_product OK")
if __name__ == "__main__": main()
