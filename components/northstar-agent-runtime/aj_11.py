"""AJ-11: Mode."""
from __future__ import annotations
VERSION = "aj_11.v1"


import collections
def mode(seq):
    return collections.Counter(seq).most_common(1)[0][0]

def main() -> None:
    assert mode([1,2,2,3]) == 2
    assert mode('aabbb') == 'b'
    print(f"aj_11 OK")
if __name__ == "__main__": main()
