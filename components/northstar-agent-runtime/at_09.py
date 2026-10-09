"""at_09: sgn -- Sign of x: -1, 0, 1."""
from __future__ import annotations
VERSION = "at_09.v1"
def sgn(x):
    return 1 if x > 0 else (-1 if x < 0 else 0)

def main() -> None:
    assert sgn(9) == 1
    assert sgn(-9) == -1
    print("at_09 sgn OK")
if __name__ == "__main__": main()
