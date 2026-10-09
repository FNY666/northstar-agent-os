"""is_prime utility."""

def is_prime(n):
    if n < 2:
        return False
    return all(n % i for i in range(2, int(n ** 0.5) + 1))


def _selftest():
    assert is_prime(13)
    assert not is_prime(15)


if __name__ == "__main__":
    _selftest()
    print("ok")
