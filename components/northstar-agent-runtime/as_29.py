"""pairwise utility."""

def pairwise(xs):
    return list(zip(xs, xs[1:]))


def _selftest():
    assert pairwise([1, 2, 3]) == [(1, 2), (2, 3)]
    assert pairwise([1]) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
