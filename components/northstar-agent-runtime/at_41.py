"""at_41: digit_sum -- Sum of digits."""
from __future__ import annotations
VERSION = "at_41.v1"
def digit_sum(n):
    return sum(int(c) for c in str(abs(n)))

def main() -> None:
    assert digit_sum(123) == 6
    assert digit_sum(0) == 0
    print("at_41 digit_sum OK")
if __name__ == "__main__": main()
