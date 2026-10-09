"""AE-module: mode -- Most common element of a non-empty list."""
from __future__ import annotations
from collections import Counter
VERSION = "ae_32.v1"
def mode(xs: list):
    if not xs:
        raise ValueError('empty')
    return Counter(xs).most_common(1)[0][0]

def main() -> None:
    assert mode([1, 2, 2, 3]) == 2
    assert mode(["a", "b", "a"]) == "a"
    assert mode([7]) == 7
    print("ae_32 mode OK")
if __name__ == "__main__": main()
