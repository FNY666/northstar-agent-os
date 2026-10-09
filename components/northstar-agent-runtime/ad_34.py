"""AD-module: flatten_one -- Flatten one level of nesting."""
from __future__ import annotations
VERSION = "ad_34.v1"
def flatten_one(xss: list) -> list:
    out = []
    for xs in xss: out.extend(xs)
    return out

def main() -> None:
    assert flatten_one([[1,2],[3]]) == [1,2,3]
    assert flatten_one([]) == []
    assert flatten_one([[]]) == []
    print("ad_34 flatten_one OK")
if __name__ == "__main__": main()
