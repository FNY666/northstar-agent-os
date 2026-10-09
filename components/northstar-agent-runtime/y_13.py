"""Y-module: sum_digits -- Sum of decimal digits."""
from __future__ import annotations
VERSION = "y_13.v1"
def sum_digits(n: int) -> int:
    return sum(int(d) for d in str(abs(n)))

def main() -> None:
    assert sum_digits(123) == 6
    assert sum_digits(-45) == 9
    print("y_13 sum_digits OK")
if __name__ == "__main__": main()
