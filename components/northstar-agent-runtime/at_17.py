"""at_17: upper -- Uppercase a string."""
from __future__ import annotations
VERSION = "at_17.v1"
def upper(s):
    return s.upper()

def main() -> None:
    assert upper('ab') == 'AB'
    assert upper('x') == 'X'
    print("at_17 upper OK")
if __name__ == "__main__": main()
