"""median utility."""

def median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2 if n else 0.0


def _selftest():
    assert median([1, 3, 2]) == 2
    assert median([1, 2, 3, 4]) == 2.5


if __name__ == "__main__":
    _selftest()
    print("ok")
