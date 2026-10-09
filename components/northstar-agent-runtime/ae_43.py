"""AE-module: days_in_month -- Days in month m of year y."""
from __future__ import annotations
VERSION = "ae_43.v1"
def days_in_month(y: int, m: int) -> int:
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    table = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return table[m - 1]

def main() -> None:
    assert days_in_month(2024, 2) == 29
    assert days_in_month(2023, 2) == 28
    assert days_in_month(2026, 1) == 31
    print("ae_43 days_in_month OK")
if __name__ == "__main__": main()
