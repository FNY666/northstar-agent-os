"""AJ-03: Flatten nested."""
from __future__ import annotations
VERSION = "aj_03.v1"


def flatten(xs):
    out = []
    for x in xs:
        (out.extend(flatten(x)) if isinstance(x, (list, tuple)) else out.append(x))
    return out

def main() -> None:
    assert flatten([1,[2,(3,[4])],5]) == [1,2,3,4,5]
    assert flatten([]) == []
    print(f"aj_03 OK")
if __name__ == "__main__": main()
