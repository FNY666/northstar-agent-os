"""AE-module: is_palindrome -- True if s reads the same ignoring case/punctuation."""
from __future__ import annotations
VERSION = "ae_12.v1"
def is_palindrome(s: str) -> bool:
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]

def main() -> None:
    assert is_palindrome("Racecar") is True
    assert is_palindrome("hello") is False
    assert is_palindrome("A man a plan a canal Panama") is True
    print("ae_12 is_palindrome OK")
if __name__ == "__main__": main()
