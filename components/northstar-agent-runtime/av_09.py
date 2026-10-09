"""Primality test for small ints."""
def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True
if __name__ == "__main__":
    assert is_prime(13) is True
    assert is_prime(1) is False
    assert is_prime(100) is False
    print("ok")
