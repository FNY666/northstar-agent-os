"""difference utility."""

def difference(a, b):
    s = set(b)
    return [x for x in a if x not in s]


def _selftest():
    assert difference([1, 2, 3], [2]) == [1, 3]
    assert difference([], []) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
