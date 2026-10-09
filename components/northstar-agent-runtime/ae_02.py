"""AE-module: is_odd -- True if integer n is odd."""
from __future__ import annotations
VERSION = "ae_02.v1"
def is_odd(n: int) -> bool:
    return n % 2 != 0

def main() -> None:
    assert is_odd(5) is True
    assert is_odd(4) is False
    assert is_odd(-3) is True
    print("ae_02 is_odd OK")
if __name__ == "__main__": main()
