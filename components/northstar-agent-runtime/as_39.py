"""symmetric_difference utility."""

def symmetric_difference(a, b):
    sb, sa = set(b), set(a)
    return [x for x in a if x not in sb] + [x for x in b if x not in sa]


def _selftest():
    assert sorted(symmetric_difference([1, 2], [2, 3])) == [1, 3]
    assert symmetric_difference([], []) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
