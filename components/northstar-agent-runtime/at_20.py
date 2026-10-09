"""at_20: cap -- Capitalize first letter."""
from __future__ import annotations
VERSION = "at_20.v1"
def cap(s):
    return s[:1].upper() + s[1:] if s else s

def main() -> None:
    assert cap('abc') == 'Abc'
    assert cap('') == ''
    print("at_20 cap OK")
if __name__ == "__main__": main()
