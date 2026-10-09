"""Y-module: count_vowels -- Count vowels in a string."""
from __future__ import annotations
VERSION = "y_07.v1"
def count_vowels(s: str) -> int:
    return sum(1 for ch in s.lower() if ch in "aeiou")

def main() -> None:
    assert count_vowels("hello") == 2
    assert count_vowels("xyz") == 0
    print("y_07 count_vowels OK")
if __name__ == "__main__": main()
