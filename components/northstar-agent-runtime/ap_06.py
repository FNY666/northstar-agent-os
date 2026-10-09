"""is_prime utility."""

def is_prime(n):
    if n < 2: return False
    i = 2
    while i*i <= n:
        if n % i == 0: return False
        i += 1
    return True


def _self_test():
    assert is_prime(7) is True
    assert is_prime(1) is False
    assert is_prime(10) is False


if __name__ == "__main__":
    _self_test()
    print("ap_06: OK")
