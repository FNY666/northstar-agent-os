"""at_46: and_mask -- Bitwise AND."""
from __future__ import annotations
VERSION = "at_46.v1"
def and_mask(a, m):
    return a & m

def main() -> None:
    assert and_mask(0b1100, 0b1010) == 0b1000
    assert and_mask(5, 0) == 0
    print("at_46 and_mask OK")
if __name__ == "__main__": main()
