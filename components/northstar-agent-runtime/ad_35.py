"""AD-module: zip_pairs -- Pair up two lists element-wise."""
from __future__ import annotations
VERSION = "ad_35.v1"
def zip_pairs(a: list, b: list) -> list:
    return [(a[i], b[i]) for i in range(min(len(a), len(b)))]

def main() -> None:
    assert zip_pairs([1,2],[3,4]) == [(1,3),(2,4)]
    assert zip_pairs([],[]) == []
    assert zip_pairs([1],[2,3]) == [(1,2)]
    print("ad_35 zip_pairs OK")
if __name__ == "__main__": main()
