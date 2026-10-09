"""union utility."""

def union(a, b):
    return list(dict.fromkeys(list(a) + list(b)))


def _selftest():
    assert union([1, 2], [2, 3]) == [1, 2, 3]
    assert union([], []) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
