"""Utility ay_18: sum_digits."""


def sum_digits(n):
    """Return sum_digits result."""
    return sum(int(d) for d in str(abs(n)))


def _run_tests():
    assert sum_digits(123) == 6
    assert sum_digits(-45) == 9


if __name__ == '__main__':
    _run_tests()
    print('OK')
