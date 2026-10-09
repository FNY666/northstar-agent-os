"""Y-module: is_even -- Return True if n is even."""
from __future__ import annotations
VERSION = "y_01.v1"
def is_even(n: int) -> bool:
    return n % 2 == 0

def main() -> None:
    assert is_even(4) is True
    assert is_even(7) is False
    print("y_01 is_even OK")
if __name__ == "__main__": main()
