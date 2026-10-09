"""at_22: count_vowels -- Count vowels in s."""
from __future__ import annotations
VERSION = "at_22.v1"
def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')

def main() -> None:
    assert count_vowels('hello') == 2
    assert count_vowels('xyz') == 0
    print("at_22 count_vowels OK")
if __name__ == "__main__": main()
