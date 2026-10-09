"""at_07: neg -- Negate a number."""
from __future__ import annotations
VERSION = "at_07.v1"
def neg(x):
    return -x

def main() -> None:
    assert neg(5) == -5
    assert neg(-2) == 2
    print("at_07 neg OK")
if __name__ == "__main__": main()
