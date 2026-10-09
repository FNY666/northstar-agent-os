"""Utility ay_17: primes_upto."""


def primes_upto(n):
    """Return primes_upto result."""
    def _prime(p):
        return p > 1 and all(p % i for i in range(2, int(p ** 0.5) + 1))
    return [i for i in range(2, n + 1) if _prime(i)]


def _run_tests():
    assert primes_upto(10) == [2, 3, 5, 7]
    assert primes_upto(1) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
