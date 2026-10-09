"""z_15: power_mod."""
from __future__ import annotations
VERSION = "z_15.v1"
def power_mod(a,e,m):
    return pow(a,e,m)

def main() -> None:
    assert power_mod(2,10,1000)==24
    assert power_mod(3,0,5)==1
    print('z_15 power_mod OK')

if __name__ == "__main__": main()
