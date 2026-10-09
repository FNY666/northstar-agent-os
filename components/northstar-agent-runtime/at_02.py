"""at_02: sub -- Subtract b from a."""
from __future__ import annotations
VERSION = "at_02.v1"
def sub(a, b):
    return a - b

def main() -> None:
    assert sub(5, 3) == 2
    assert sub(0, 4) == -4
    print("at_02 sub OK")
if __name__ == "__main__": main()
