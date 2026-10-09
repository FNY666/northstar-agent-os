"""z_38: is_power2."""
from __future__ import annotations
VERSION = "z_38.v1"
def is_power2(n):
    return n>0 and (n&(n-1))==0

def main() -> None:
    assert is_power2(16)
    assert not is_power2(18)
    print('z_38 is_power2 OK')

if __name__ == "__main__": main()
