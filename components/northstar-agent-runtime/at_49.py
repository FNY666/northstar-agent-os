"""at_49: to_bin -- Binary string of n."""
from __future__ import annotations
VERSION = "at_49.v1"
def to_bin(n):
    return bin(n)[2:]

def main() -> None:
    assert to_bin(5) == '101'
    assert to_bin(0) == '0'
    print("at_49 to_bin OK")
if __name__ == "__main__": main()
