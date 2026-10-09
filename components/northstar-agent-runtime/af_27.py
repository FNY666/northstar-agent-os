"""AF-module: partition -- Split items into (matching, non-matching) by predicate."""
from __future__ import annotations
VERSION = "af_27"
def partition(pred, xs: list) -> tuple:
    yes, no = [], []
    for x in xs:
        (yes if pred(x) else no).append(x)
    return yes, no

def main() -> None:
    assert partition(lambda x: x % 2 == 0, [1, 2, 3, 4]) == ([2, 4], [1, 3])
    assert partition(bool, []) == ([], [])
    assert partition(lambda x: True, [1]) == ([1], [])
    print("af_27 partition OK")
if __name__ == "__main__": main()
