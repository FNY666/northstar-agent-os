"""z_06: is_anagram."""
from __future__ import annotations
VERSION = "z_06.v1"
def is_anagram(a, b):
    from collections import Counter
    return Counter(a) == Counter(b)

def main() -> None:
    assert is_anagram('listen','silent')
    assert not is_anagram('ab','ac')
    print('z_06 is_anagram OK')

if __name__ == "__main__": main()
