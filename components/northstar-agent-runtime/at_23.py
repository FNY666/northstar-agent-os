"""at_23: is_palindrome -- True if s reads the same backwards."""
from __future__ import annotations
VERSION = "at_23.v1"
def is_palindrome(s):
    return s == s[::-1]

def main() -> None:
    assert is_palindrome('aba') is True
    assert is_palindrome('abc') is False
    print("at_23 is_palindrome OK")
if __name__ == "__main__": main()
