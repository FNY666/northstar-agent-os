"""at_42: digit_count -- Number of digits."""
from __future__ import annotations
VERSION = "at_42.v1"
def digit_count(n):
    return len(str(abs(n)))

def main() -> None:
    assert digit_count(123) == 3
    assert digit_count(0) == 1
    print("at_42 digit_count OK")
if __name__ == "__main__": main()
