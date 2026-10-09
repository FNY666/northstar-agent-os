"""rotate utility."""

def rotate(xs, k):
    k %= len(xs) if xs else 1
    return xs[k:] + xs[:k]


def _selftest():
    assert rotate([1, 2, 3, 4], 1) == [2, 3, 4, 1]
    assert rotate([], 5) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
