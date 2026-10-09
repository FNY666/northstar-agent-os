"""AD-module: list_len -- Length of a list without len()."""
from __future__ import annotations
VERSION = "ad_30.v1"
def list_len(xs: list) -> int:
    n = 0
    for _ in xs: n += 1
    return n

def main() -> None:
    assert list_len([1,2,3]) == 3
    assert list_len([]) == 0
    assert list_len(["a"]) == 1
    print("ad_30 list_len OK")
if __name__ == "__main__": main()
