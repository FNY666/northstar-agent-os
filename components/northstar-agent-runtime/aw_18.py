"""True if n is a prime number."""
def is_prime(n):
    if n < 2:
        return False
    return all(n % i for i in range(2, int(n ** 0.5) + 1))
if __name__ == "__main__":
    assert is_prime(2) is True
    assert is_prime(15) is False
    assert is_prime(97) is True
    print("ok")
