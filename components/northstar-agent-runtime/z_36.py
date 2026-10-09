"""z_36: count_bits."""
from __future__ import annotations
VERSION = "z_36.v1"
def count_bits(n):
    return bin(n).count('1')

def main() -> None:
    assert count_bits(7)==3
    assert count_bits(0)==0
    print('z_36 count_bits OK')

if __name__ == "__main__": main()
