"""Y-module: is_anagram -- Anagram check (case-insensitive, spaces ignored)."""
from __future__ import annotations
VERSION = "y_20.v1"
def is_anagram(a: str, b: str) -> bool:
    f = lambda s: sorted(ch.lower() for ch in s if not ch.isspace())
    return f(a) == f(b)

def main() -> None:
    assert is_anagram("listen", "silent") is True
    assert is_anagram("abc", "abd") is False
    print("y_20 is_anagram OK")
if __name__ == "__main__": main()
