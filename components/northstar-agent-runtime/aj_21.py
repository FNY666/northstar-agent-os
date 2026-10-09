"""AJ-21: Palindrome check."""
from __future__ import annotations
VERSION = "aj_21.v1"


def is_pal(s):
    t = ''.join(c.lower() for c in str(s) if c.isalnum())
    return t == t[::-1]

def main() -> None:
    assert is_pal('A man, a plan, a canal: Panama')
    assert not is_pal('hello')
    print(f"aj_21 OK")
if __name__ == "__main__": main()
