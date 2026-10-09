"""flatten utility."""

def flatten(xs):
    out = []
    for x in xs:
        out.extend(flatten(x) if isinstance(x, list) else [x])
    return out


def _selftest():
    assert flatten([1, [2, [3]], 4]) == [1, 2, 3, 4]
    assert flatten([]) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
