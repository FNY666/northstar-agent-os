"""AJ-22: Anagram check."""
from __future__ import annotations
VERSION = "aj_22.v1"


import collections
def is_anagram(a, b):
    return collections.Counter(a) == collections.Counter(b)

def main() -> None:
    assert is_anagram('listen','silent')
    assert not is_anagram('abc','abd')
    print(f"aj_22 OK")
if __name__ == "__main__": main()
