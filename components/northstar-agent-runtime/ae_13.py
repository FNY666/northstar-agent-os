"""AE-module: count_vowels -- Number of aeiou in s (case-insensitive)."""
from __future__ import annotations
VERSION = "ae_13.v1"
def count_vowels(s: str) -> int:
    return sum(1 for c in s.lower() if c in 'aeiou')

def main() -> None:
    assert count_vowels("hello") == 2
    assert count_vowels("xyz") == 0
    assert count_vowels("AEIOU") == 5
    print("ae_13 count_vowels OK")
if __name__ == "__main__": main()
