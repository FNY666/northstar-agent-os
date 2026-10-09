"""at_48: popcount -- Count set bits."""
from __future__ import annotations
VERSION = "at_48.v1"
def popcount(n):
    return bin(n).count('1')

def main() -> None:
    assert popcount(7) == 3
    assert popcount(0) == 0
    print("at_48 popcount OK")
if __name__ == "__main__": main()
