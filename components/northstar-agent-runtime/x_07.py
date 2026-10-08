"""X-module: flatten1 -- Flatten one level of nesting."""
from __future__ import annotations
VERSION = "x_07.v1"
def flatten1(xs: list) -> list:
    out = []
    for x in xs:
        out.extend(x if isinstance(x, list) else [x])
    return out

def main() -> None:
    assert flatten1([[1, 2], 3, [4]]) == [1, 2, 3, 4]
    assert flatten1([]) == []
    print("x_07 flatten1 OK")
if __name__ == "__main__": main()
