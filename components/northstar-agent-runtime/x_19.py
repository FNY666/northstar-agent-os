"""X-module: is_anagram -- Check anagram ignoring case/spacing."""
from __future__ import annotations
VERSION = "x_19.v1"
def is_anagram(a: str, b: str) -> bool:
    norm = lambda s: sorted(c.lower() for c in s if c.isalnum())
    return norm(a) == norm(b)

def main() -> None:
    assert is_anagram("listen", "silent")
    assert not is_anagram("abc", "abd")
    print("x_19 is_anagram OK")
if __name__ == "__main__": main()
