"""at_06: pow2 -- Raise 2 to the power n."""
from __future__ import annotations
VERSION = "at_06.v1"
def pow2(n):
    return 2 ** max(0, n)

def main() -> None:
    assert pow2(3) == 8
    assert pow2(0) == 1
    print("at_06 pow2 OK")
if __name__ == "__main__": main()
