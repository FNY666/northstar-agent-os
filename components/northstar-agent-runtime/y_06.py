"""Y-module: is_palindrome -- Case-insensitive palindrome check (alnum only)."""
from __future__ import annotations
VERSION = "y_06.v1"
def is_palindrome(s: str) -> bool:
    t = "".join(ch.lower() for ch in s if ch.isalnum())
    return t == t[::-1]

def main() -> None:
    assert is_palindrome("A man a plan a canal Panama") is True
    assert is_palindrome("hello") is False
    print("y_06 is_palindrome OK")
if __name__ == "__main__": main()
