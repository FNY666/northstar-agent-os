"""take utility."""

def take(xs, n):
    return xs[:n]


def _selftest():
    assert take([1, 2, 3], 2) == [1, 2]
    assert take([1], 5) == [1]


if __name__ == "__main__":
    _selftest()
    print("ok")
