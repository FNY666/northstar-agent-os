"""z_37: reverse_bits8."""
from __future__ import annotations
VERSION = "z_37.v1"
def reverse_bits8(n):
    return int(f'{n:08b}'[::-1],2)

def main() -> None:
    assert reverse_bits8(0b11010000)==0b00001011
    assert reverse_bits8(0)==0
    print('z_37 reverse_bits8 OK')

if __name__ == "__main__": main()
