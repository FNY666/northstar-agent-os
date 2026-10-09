"""at_10: is_even -- True if x is even."""
from __future__ import annotations
VERSION = "at_10.v1"
def is_even(x):
    return x % 2 == 0

def main() -> None:
    assert is_even(4) is True
    assert is_even(5) is False
    print("at_10 is_even OK")
if __name__ == "__main__": main()
