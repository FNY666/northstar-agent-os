"""at_16: rev -- Reverse a string."""
from __future__ import annotations
VERSION = "at_16.v1"
def rev(s):
    return s[::-1]

def main() -> None:
    assert rev('abc') == 'cba'
    assert rev('') == ''
    print("at_16 rev OK")
if __name__ == "__main__": main()
