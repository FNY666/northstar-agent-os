"""Utility ay_50: repeat_join."""


def repeat_join(s, n, sep=', '):
    """Return repeat_join result."""
    return sep.join([s]*n)


def _run_tests():
    assert repeat_join('x', 3) == 'x, x, x'
    assert repeat_join('x', 0) == ''


if __name__ == '__main__':
    _run_tests()
    print('OK')
