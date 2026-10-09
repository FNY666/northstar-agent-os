"""z_40: xor_swap."""
from __future__ import annotations
VERSION = "z_40.v1"
def xor_swap(a,b):
    a^=b; b^=a; a^=b
    return a,b

def main() -> None:
    assert xor_swap(3,5)==(5,3)
    assert xor_swap(0,9)==(9,0)
    print('z_40 xor_swap OK')

if __name__ == "__main__": main()
