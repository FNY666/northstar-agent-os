"""AE-module: flatten -- One-level flatten of a list of lists."""
from __future__ import annotations
VERSION = "ae_20.v1"
def flatten(xs: list) -> list:
    out = []
    for x in xs:
        if isinstance(x, list):
            out.extend(x)
        else:
            out.append(x)
    return out

def main() -> None:
    assert flatten([[1, 2], [3]]) == [1, 2, 3]
    assert flatten([1, [2]]) == [1, 2]
    assert flatten([]) == []
    print("ae_20 flatten OK")
if __name__ == "__main__": main()
