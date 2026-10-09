"""AJ-35: Counter diff."""
from __future__ import annotations
VERSION = "aj_35.v1"


import collections
def counter_diff(a, b):
    ca, cb = collections.Counter(a), collections.Counter(b)
    return dict(ca - cb), dict(cb - ca)

def main() -> None:
    assert counter_diff([1,1,2],[1,3]) == ({1:1,2:1},{3:1})
    assert counter_diff([],[]) == ({}, {})
    print(f"aj_35 OK")
if __name__ == "__main__": main()
