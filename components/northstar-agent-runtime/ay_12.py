"""Utility ay_12: fib_n."""


def fib_n(n):
    """Return fib_n result."""
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def _run_tests():
    assert fib_n(0) == 0
    assert fib_n(1) == 1
    assert fib_n(10) == 55


if __name__ == '__main__':
    _run_tests()
    print('OK')
