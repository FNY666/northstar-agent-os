"""au_06: Primality test."""
def is_prime(n):
    """True if n is prime."""
    if n < 2:
        return False
    i = 2
    while i*i <= n:
        if n % i == 0:
            return False
        i += 1
    return True

def _run_tests():
    assert is_prime(17)
    assert not is_prime(18)

if __name__ == "__main__":
    _run_tests()
    print("au_06 OK")
