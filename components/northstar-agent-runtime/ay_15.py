"""Utility ay_15: lcm_pair."""


def lcm_pair(a, b):
    """Return lcm_pair result."""
    import math
    return abs(a * b) // math.gcd(a, b) if a and b else 0


def _run_tests():
    assert lcm_pair(4, 6) == 12
    assert lcm_pair(0, 5) == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
