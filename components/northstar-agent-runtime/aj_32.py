"""AJ-32: Dict invert."""
from __future__ import annotations
VERSION = "aj_32.v1"


def invert(d):
    return {v: k for k, v in d.items()}

def main() -> None:
    assert invert({'a':1,'b':2}) == {1:'a',2:'b'}
    assert invert({}) == {}
    print(f"aj_32 OK")
if __name__ == "__main__": main()
