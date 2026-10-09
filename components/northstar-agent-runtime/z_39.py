"""z_39: next_pow2."""
from __future__ import annotations
VERSION = "z_39.v1"
def next_pow2(n):
    p=1
    while p<n: p<<=1
    return p

def main() -> None:
    assert next_pow2(5)==8
    assert next_pow2(8)==8
    print('z_39 next_pow2 OK')

if __name__ == "__main__": main()
