"""group_by utility."""

def group_by(xs, key):
    o = {}
    for x in xs:
        o.setdefault(key(x), []).append(x)
    return o


def _selftest():
    assert group_by([1, 2, 3, 4], lambda x: x % 2) == {1: [1, 3], 0: [2, 4]}
    assert group_by([], str) == {}


if __name__ == "__main__":
    _selftest()
    print("ok")
