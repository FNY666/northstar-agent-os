"""sliding_window utility."""

def sliding_window(xs, n):
    return [xs[i:i + n] for i in range(len(xs) - n + 1)]


def _selftest():
    assert sliding_window([1, 2, 3], 2) == [[1, 2], [2, 3]]
    assert sliding_window([1], 2) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
