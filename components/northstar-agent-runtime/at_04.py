"""at_04: div -- Floor divide a by b."""
from __future__ import annotations
VERSION = "at_04.v1"
def div(a, b):
    return a // b if b else 0

def main() -> None:
    assert div(7, 2) == 3
    assert div(5, 0) == 0
    print("at_04 div OK")
if __name__ == "__main__": main()
