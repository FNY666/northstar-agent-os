"""AE-module: drop -- List without the first n elements."""
from __future__ import annotations
VERSION = "ae_24.v1"
def drop(xs: list, n: int) -> list:
    return xs[n:]

def main() -> None:
    assert drop([1, 2, 3], 1) == [2, 3]
    assert drop([1], 5) == []
    assert drop([], 0) == []
    print("ae_24 drop OK")
if __name__ == "__main__": main()
