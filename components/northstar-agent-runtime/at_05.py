"""at_05: mod -- Modulo a by b."""
from __future__ import annotations
VERSION = "at_05.v1"
def mod(a, b):
    return a % b if b else 0

def main() -> None:
    assert mod(7, 3) == 1
    assert mod(5, 0) == 0
    print("at_05 mod OK")
if __name__ == "__main__": main()
