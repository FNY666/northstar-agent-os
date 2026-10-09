"""AD-module: is_palindrome -- Check if a string reads the same backwards."""
from __future__ import annotations
VERSION = "ad_40.v1"
def is_palindrome(s: str) -> bool:
    return s == s[::-1]

def main() -> None:
    assert is_palindrome("racecar") is True
    assert is_palindrome("ab") is False
    assert is_palindrome("") is True
    print("ad_40 is_palindrome OK")
if __name__ == "__main__": main()
