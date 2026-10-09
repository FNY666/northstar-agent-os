"""cycle_n utility."""

def cycle_n(xs, n):
    return [xs[i % len(xs)] for i in range(n)] if xs else []


def _selftest():
    assert cycle_n([1, 2], 5) == [1, 2, 1, 2, 1]
    assert cycle_n([], 3) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
