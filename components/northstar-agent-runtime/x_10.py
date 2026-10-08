"""X-module: word_count -- Count words in text."""
from __future__ import annotations
VERSION = "x_10.v1"
def word_count(t: str) -> int:
    return len(t.split())

def main() -> None:
    assert word_count("hello world") == 2
    assert word_count("  ") == 0
    assert word_count("one") == 1
    print("x_10 word_count OK")
if __name__ == "__main__": main()
