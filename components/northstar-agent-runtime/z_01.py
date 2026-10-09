"""z_01: zfill_num."""
from __future__ import annotations
VERSION = "z_01.v1"
def zfill_num(n, w):
    return str(n).zfill(w)

def main() -> None:
    assert zfill_num(42, 5) == '00042'
    assert zfill_num(7, 1) == '7'
    print('z_01 zfill_num OK')

if __name__ == "__main__": main()
