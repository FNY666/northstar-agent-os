"""is_sorted utility."""

def is_sorted(xs):
    return all(a <= b for a, b in zip(xs, xs[1:]))


def _selftest():
    assert is_sorted([1, 2, 3])
    assert not is_sorted([3, 1])


if __name__ == "__main__":
    _selftest()
    print("ok")
