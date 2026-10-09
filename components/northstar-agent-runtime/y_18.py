"""Y-module: flatten1 -- Flatten one nesting level."""
from __future__ import annotations
VERSION = "y_18.v1"
def flatten1(xss: list) -> list:
    out = []
    for xs in xss: out.extend(xs)
    return out

def main() -> None:
    assert flatten1([[1, 2], [3]]) == [1, 2, 3]
    assert flatten1([]) == []
    print("y_18 flatten1 OK")
if __name__ == "__main__": main()
