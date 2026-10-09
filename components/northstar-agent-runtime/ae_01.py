"""AE-module: is_even -- True if integer n is even."""
from __future__ import annotations
VERSION = "ae_01.v1"
def is_even(n: int) -> bool:
    return n % 2 == 0

def main() -> None:
    assert is_even(4) is True
    assert is_even(5) is False
    assert is_even(0) is True
    print("ae_01 is_even OK")
if __name__ == "__main__": main()
