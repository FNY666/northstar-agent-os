"""at_11: is_odd -- True if x is odd."""
from __future__ import annotations
VERSION = "at_11.v1"
def is_odd(x):
    return x % 2 == 1

def main() -> None:
    assert is_odd(7) is True
    assert is_odd(8) is False
    print("at_11 is_odd OK")
if __name__ == "__main__": main()
