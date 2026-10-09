"""AD-module: vowel_count -- Count vowels in a string."""
from __future__ import annotations
VERSION = "ad_41.v1"
def vowel_count(s: str) -> int:
    return sum(1 for c in s.lower() if c in "aeiou")

def main() -> None:
    assert vowel_count("hello") == 2
    assert vowel_count("xyz") == 0
    assert vowel_count("") == 0
    print("ad_41 vowel_count OK")
if __name__ == "__main__": main()
