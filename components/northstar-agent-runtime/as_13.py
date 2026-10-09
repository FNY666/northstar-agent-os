"""chunk utility."""

def chunk(xs, n):
    return [xs[i:i + n] for i in range(0, len(xs), n)]


def _selftest():
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert chunk([], 3) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
