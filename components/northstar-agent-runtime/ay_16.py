"""Utility ay_16: is_prime_n."""


def is_prime_n(n):
    """Return is_prime_n result."""
    return n > 1 and all(n % i for i in range(2, int(n**0.5)+1))


def _run_tests():
    assert is_prime_n(7) is True
    assert is_prime_n(4) is False
    assert is_prime_n(1) is False


if __name__ == '__main__':
    _run_tests()
    print('OK')
