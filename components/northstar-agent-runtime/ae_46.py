"""AE-module: count_true -- Number of truthy elements in xs."""
from __future__ import annotations
VERSION = "ae_46.v1"
def count_true(xs: list) -> int:
    return sum(1 for x in xs if x)

def main() -> None:
    assert count_true([True, False, True]) == 2
    assert count_true([]) == 0
    assert count_true([0, '', None]) == 0
    print("ae_46 count_true OK")
if __name__ == "__main__": main()
