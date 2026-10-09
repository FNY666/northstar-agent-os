"""AF-module: jaccard -- Jaccard similarity of two iterables treated as sets."""
from __future__ import annotations
VERSION = "af_14"
def jaccard(a, b) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)

def main() -> None:
    assert jaccard([1, 2], [2, 3]) == 1 / 3
    assert jaccard([1, 2], [2, 4]) == 1 / 3
    assert jaccard([], []) == 1.0
    assert jaccard([1], [1]) == 1.0
    print("af_14 jaccard OK")
if __name__ == "__main__": main()
