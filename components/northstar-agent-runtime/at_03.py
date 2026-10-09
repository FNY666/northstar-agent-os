"""at_03: mul -- Multiply two numbers."""
from __future__ import annotations
VERSION = "at_03.v1"
def mul(a, b):
    return a * b

def main() -> None:
    assert mul(3, 4) == 12
    assert mul(-2, 5) == -10
    print("at_03 mul OK")
if __name__ == "__main__": main()
