"""AD-module: word_count -- Count words in a string."""
from __future__ import annotations
VERSION = "ad_20.v1"
def word_count(s: str) -> int:
    return len(s.split())

def main() -> None:
    assert word_count("a b c") == 3
    assert word_count("") == 0
    assert word_count("  x  ") == 1
    print("ad_20 word_count OK")
if __name__ == "__main__": main()
