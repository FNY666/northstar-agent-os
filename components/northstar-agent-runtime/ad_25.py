"""AD-module: last_n -- Return the last n items of a list."""
from __future__ import annotations
VERSION = "ad_25.v1"
def last_n(xs: list, n: int) -> list:
    return xs[-n:] if n else []

def main() -> None:
    assert last_n([1,2,3], 2) == [2,3]
    assert last_n([1], 0) == []
    assert last_n([], 3) == []
    print("ad_25 last_n OK")
if __name__ == "__main__": main()
