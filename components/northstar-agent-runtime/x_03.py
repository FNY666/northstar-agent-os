"""X-module: is_palindrome -- Check palindrome ignoring case/spacing."""
from __future__ import annotations
VERSION = "x_03.v1"
def is_palindrome(s: str) -> bool:
    t = "".join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]

def main() -> None:
    assert is_palindrome("Race car")
    assert is_palindrome("abc") is False
    assert is_palindrome("")
    print("x_03 is_palindrome OK")
if __name__ == "__main__": main()
