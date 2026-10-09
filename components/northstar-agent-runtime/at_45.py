"""at_45: xor_swap_note -- XOR two ints."""
from __future__ import annotations
VERSION = "at_45.v1"
def xor(a, b):
    return a ^ b

def main() -> None:
    assert xor(5, 3) == 6
    assert xor(0, 0) == 0
    print("at_45 xor_swap_note OK")
if __name__ == "__main__": main()
