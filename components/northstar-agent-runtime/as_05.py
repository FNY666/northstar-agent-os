"""factorial utility."""

def factorial(n):
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r


def _selftest():
    assert factorial(5) == 120
    assert factorial(0) == 1


if __name__ == "__main__":
    _selftest()
    print("ok")
