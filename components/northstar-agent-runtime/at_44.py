"""at_44: ceildiv -- Ceiling division."""
from __future__ import annotations
VERSION = "at_44.v1"
def ceildiv(a, b):
    return -(-a // b) if b else 0

def main() -> None:
    assert ceildiv(7, 2) == 4
    assert ceildiv(6, 3) == 2
    print("at_44 ceildiv OK")
if __name__ == "__main__": main()
