"""drop utility."""

def drop(xs, n):
    return xs[n:]


def _selftest():
    assert drop([1, 2, 3], 2) == [3]
    assert drop([1], 5) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
