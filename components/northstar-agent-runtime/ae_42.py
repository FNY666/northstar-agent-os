"""AE-module: is_leap_year -- True for Gregorian leap years."""
from __future__ import annotations
VERSION = "ae_42.v1"
def is_leap_year(y: int) -> bool:
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)

def main() -> None:
    assert is_leap_year(2024) is True
    assert is_leap_year(1900) is False
    assert is_leap_year(2000) is True
    print("ae_42 is_leap_year OK")
if __name__ == "__main__": main()
