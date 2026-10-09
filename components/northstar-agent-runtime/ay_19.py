"""Utility ay_19: digital_root."""


def digital_root(n):
    """Return digital_root result."""
    n = abs(n)
    while n > 9:
        n = sum(int(d) for d in str(n))
    return n


def _run_tests():
    assert digital_root(38) == 2
    assert digital_root(0) == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
