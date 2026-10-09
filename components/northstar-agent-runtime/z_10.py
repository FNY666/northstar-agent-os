"""z_10: gcd."""
from __future__ import annotations
VERSION = "z_10.v1"
def gcd(a,b):
    while b:
        a,b=b,a%b
    return abs(a)

def main() -> None:
    assert gcd(12,18)==6
    assert gcd(7,13)==1
    print('z_10 gcd OK')

if __name__ == "__main__": main()
