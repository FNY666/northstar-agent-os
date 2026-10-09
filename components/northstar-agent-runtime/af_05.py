"""AF-module: unique_ordered -- Remove duplicates, keeping first-seen order."""
from __future__ import annotations
VERSION = "af_05"
def unique_ordered(xs: list) -> list:
    seen: set = set()
    out: list = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def main() -> None:
    assert unique_ordered([3, 1, 3, 2, 1]) == [3, 1, 2]
    assert unique_ordered([]) == []
    assert unique_ordered('abac') == ['a', 'b', 'c']
    print("af_05 unique_ordered OK")
if __name__ == "__main__": main()
