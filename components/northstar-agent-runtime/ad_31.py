"""AD-module: contains -- Check if a list contains a value."""
from __future__ import annotations
VERSION = "ad_31.v1"
def contains(xs: list, v) -> bool:
    for x in xs:
        if x == v: return True
    return False

def main() -> None:
    assert contains([1,2,3], 2) is True
    assert contains([1,2,3], 9) is False
    assert contains([], 1) is False
    print("ad_31 contains OK")
if __name__ == "__main__": main()
