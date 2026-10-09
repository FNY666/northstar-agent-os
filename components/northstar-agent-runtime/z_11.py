"""z_11: lcm."""
from __future__ import annotations
VERSION = "z_11.v1"
def lcm(a,b):
    return abs(a*b)//z_gcd(a,b) if a and b else 0
def z_gcd(a,b):
    while b: a,b=b,a%b
    return abs(a)

def main() -> None:
    assert lcm(4,6)==12
    assert lcm(7,5)==35
    print('z_11 lcm OK')

if __name__ == "__main__": main()
