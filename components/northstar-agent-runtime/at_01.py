"""at_01: add -- Add two numbers."""
from __future__ import annotations
VERSION = "at_01.v1"
def add(a, b):
    return a + b

def main() -> None:
    assert add(2, 3) == 5
    assert add(-1, 1) == 0
    print("at_01 add OK")
if __name__ == "__main__": main()
