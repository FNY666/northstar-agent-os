"""Y-module: is_perfect_square -- Check perfect square."""
from __future__ import annotations
VERSION = "y_33.v1"
def is_perfect_square(n: int) -> bool:
    r = int(n ** 0.5)
    return n >= 0 and r * r == n

def main() -> None:
    assert is_perfect_square(49) is True
    assert is_perfect_square(50) is False
    print("y_33 is_perfect_square OK")
if __name__ == "__main__": main()
