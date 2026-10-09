"""intersection utility."""

def intersection(a, b):
    s = set(b)
    return [x for x in a if x in s]


def _selftest():
    assert intersection([1, 2, 3], [2, 3, 4]) == [2, 3]
    assert intersection([], [1]) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
