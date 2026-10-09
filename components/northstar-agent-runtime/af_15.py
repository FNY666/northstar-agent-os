"""AF-module: top_n -- The n most common items of an iterable, most common first."""
from __future__ import annotations
VERSION = "af_15"
from collections import Counter
def top_n(xs, n: int) -> list:
    return [item for item, _ in Counter(xs).most_common(max(0, n))]

def main() -> None:
    assert top_n([1, 2, 2, 3, 3, 3], 2) == [3, 2]
    assert top_n([], 3) == []
    assert top_n('aaabbc', 1) == ['a']
    print("af_15 top_n OK")
if __name__ == "__main__": main()
