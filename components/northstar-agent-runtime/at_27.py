"""at_27: flatten -- Flatten one level."""
from __future__ import annotations
VERSION = "at_27.v1"
def flatten(xss):
    return [x for xs in xss for x in xs]

def main() -> None:
    assert flatten([[1], [2, 3]]) == [1, 2, 3]
    assert flatten([]) == []
    print("at_27 flatten OK")
if __name__ == "__main__": main()
