"""AE-module: all_equal -- True if every element equals the first."""
from __future__ import annotations
VERSION = "ae_45.v1"
def all_equal(xs: list) -> bool:
    return all(x == xs[0] for x in xs)

def main() -> None:
    assert all_equal([2, 2, 2]) is True
    assert all_equal([1, 2]) is False
    assert all_equal([]) is True
    print("ae_45 all_equal OK")
if __name__ == "__main__": main()
