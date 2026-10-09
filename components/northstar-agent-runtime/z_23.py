"""z_23: palindrome."""
from __future__ import annotations
VERSION = "z_23.v1"
def palindrome(s):
    t=''.join(c.lower() for c in s if c.isalnum())
    return t==t[::-1]

def main() -> None:
    assert palindrome('A man a plan a canal Panama')
    assert not palindrome('hello')
    print('z_23 palindrome OK')

if __name__ == "__main__": main()
