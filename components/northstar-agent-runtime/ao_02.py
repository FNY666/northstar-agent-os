"""ao_02: is_prime utility (stdlib only)."""

def is_prime(n):
    if n < 2: return False
    i = 2
    while i * i <= n:
        if n % i == 0: return False
        i += 1
    return True


def _self_test():
    assert is_prime(7), 'is_prime(7)'
    assert not is_prime(9), 'not is_prime(9)'
    assert not is_prime(1), 'not is_prime(1)'


if __name__ == "__main__":
    _self_test()
    print("ok")
