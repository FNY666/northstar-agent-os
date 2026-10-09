"""Utility ay_14: gcd_pair."""


def gcd_pair(a, b):
    """Return gcd_pair result."""
    import math
    return math.gcd(a, b)


def _run_tests():
    assert gcd_pair(12, 18) == 6
    assert gcd_pair(7, 5) == 1


if __name__ == '__main__':
    _run_tests()
    print('OK')
