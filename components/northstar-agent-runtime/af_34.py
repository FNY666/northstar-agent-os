"""AF-module: first_duplicate -- First repeated element, or None."""
from __future__ import annotations
VERSION = "af_34"
def first_duplicate(xs: list):
    seen: set = set()
    for x in xs:
        if x in seen:
            return x
        seen.add(x)
    return None

def main() -> None:
    assert first_duplicate([1, 2, 3, 2, 1]) == 2
    assert first_duplicate([1, 2, 3]) is None
    assert first_duplicate([]) is None
    print("af_34 first_duplicate OK")
if __name__ == "__main__": main()
