"""AD-module: unique -- Remove duplicates preserving order."""
from __future__ import annotations
VERSION = "ad_33.v1"
def unique(xs: list) -> list:
    out = []
    for x in xs:
        if x not in out: out.append(x)
    return out

def main() -> None:
    assert unique([1,2,2,3,1]) == [1,2,3]
    assert unique([]) == []
    assert unique([1,1]) == [1]
    print("ad_33 unique OK")
if __name__ == "__main__": main()
