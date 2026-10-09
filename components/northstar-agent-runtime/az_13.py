"""LCM of two ints. stdlib only."""

import math

def lcm2(a, b):
    return abs(a*b) // math.gcd(a, b)

def test():
    assert lcm2(4, 6) == 12
    assert lcm2(7, 5) == 35
    assert lcm2(1, 9) == 9

if __name__ == '__main__':
    test(); print('ok')
