"""GCD of two ints. stdlib only."""

import math

def gcd2(a, b):
    return math.gcd(a, b)

def test():
    assert gcd2(12, 18) == 6
    assert gcd2(7, 5) == 1
    assert gcd2(0, 9) == 9

if __name__ == '__main__':
    test(); print('ok')
