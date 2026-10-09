"""AF-module: flatten_one -- Flatten one level of nesting in a list."""
from __future__ import annotations
VERSION = "af_04"
def flatten_one(xss: list) -> list:
    out: list = []
    for xs in xss:
        out.extend(xs)
    return out

def main() -> None:
    assert flatten_one([[1, 2], [3], []]) == [1, 2, 3]
    assert flatten_one([]) == []
    assert flatten_one([[], [1]]) == [1]
    print("af_04 flatten_one OK")
if __name__ == "__main__": main()
