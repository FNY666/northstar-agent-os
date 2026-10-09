"""Y-module: is_odd -- Return True if n is odd."""
from __future__ import annotations
VERSION = "y_02.v1"
def is_odd(n: int) -> bool:
    return n % 2 == 1

def main() -> None:
    assert is_odd(3) is True
    assert is_odd(8) is False
    print("y_02 is_odd OK")
if __name__ == "__main__": main()
