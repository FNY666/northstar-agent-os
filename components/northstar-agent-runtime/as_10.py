"""sum_digits utility."""

def sum_digits(n):
    return sum(int(d) for d in str(abs(n)))


def _selftest():
    assert sum_digits(123) == 6
    assert sum_digits(0) == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
