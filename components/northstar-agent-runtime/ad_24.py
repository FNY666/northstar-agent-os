"""AD-module: tail -- Return all but the first item of a list."""
from __future__ import annotations
VERSION = "ad_24.v1"
def tail(xs: list) -> list:
    return xs[1:]

def main() -> None:
    assert tail([1,2,3]) == [2,3]
    assert tail([]) == []
    assert tail([9]) == []
    print("ad_24 tail OK")
if __name__ == "__main__": main()
