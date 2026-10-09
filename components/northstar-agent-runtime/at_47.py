"""at_47: or_mask -- Bitwise OR."""
from __future__ import annotations
VERSION = "at_47.v1"
def or_mask(a, m):
    return a | m

def main() -> None:
    assert or_mask(0b1100, 0b1010) == 0b1110
    assert or_mask(0, 0) == 0
    print("at_47 or_mask OK")
if __name__ == "__main__": main()
