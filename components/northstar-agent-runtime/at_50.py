"""at_50: to_hex -- Hex string of n."""
from __future__ import annotations
VERSION = "at_50.v1"
def to_hex(n):
    return hex(n)[2:]

def main() -> None:
    assert to_hex(255) == 'ff'
    assert to_hex(16) == '10'
    print("at_50 to_hex OK")
if __name__ == "__main__": main()
