"""gcd utility."""

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _selftest():
    assert gcd(12, 18) == 6
    assert gcd(7, 5) == 1


if __name__ == "__main__":
    _selftest()
    print("ok")
