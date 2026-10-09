"""at_35: uniq_sort -- Sorted unique items."""
from __future__ import annotations
VERSION = "at_35.v1"
def uniq_sort(xs):
    return sorted(set(xs))

def main() -> None:
    assert uniq_sort([3, 1, 3]) == [1, 3]
    assert uniq_sort([]) == []
    print("at_35 uniq_sort OK")
if __name__ == "__main__": main()
