"""zip_fill utility."""

def zip_fill(a, b, f=None):
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else f, b[i] if i < len(b) else f) for i in range(n)]


def _selftest():
    assert zip_fill([1], [1, 2], 0) == [(1, 1), (0, 2)]
    assert zip_fill([], [], 0) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
