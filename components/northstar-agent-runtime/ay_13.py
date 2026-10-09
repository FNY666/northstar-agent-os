"""Utility ay_13: factorial_n."""


def factorial_n(n):
    """Return factorial_n result."""
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r


def _run_tests():
    assert factorial_n(0) == 1
    assert factorial_n(5) == 120


if __name__ == '__main__':
    _run_tests()
    print('OK')
