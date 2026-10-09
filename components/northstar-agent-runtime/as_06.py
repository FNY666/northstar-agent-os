"""fibonacci utility."""

def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def _selftest():
    assert fibonacci(10) == 55
    assert fibonacci(0) == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
