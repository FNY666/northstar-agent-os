"""AF-module: is_palindrome -- True if text reads the same ignoring case and non-alphanumerics."""
from __future__ import annotations
VERSION = "af_01"
import re
def is_palindrome(s: str) -> bool:
    t = re.sub(r'[^a-z0-9]', '', s.lower())
    return t == t[::-1]

def main() -> None:
    assert is_palindrome('Racecar') is True
    assert is_palindrome('A man, a plan, a canal: Panama') is True
    assert is_palindrome('hello') is False
    print("af_01 is_palindrome OK")
if __name__ == "__main__": main()
