"""Y-module: count_words -- Count whitespace-separated words."""
from __future__ import annotations
VERSION = "y_22.v1"
def count_words(s: str) -> int:
    return len(s.split())

def main() -> None:
    assert count_words("a b c") == 3
    assert count_words("  ") == 0
    print("y_22 count_words OK")
if __name__ == "__main__": main()
