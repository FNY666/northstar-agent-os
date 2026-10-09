"""ao_09: flatten utility (stdlib only)."""

def flatten(xs):
    out = []
    for x in xs:
        out.extend(flatten(x) if isinstance(x, list) else [x])
    return out


def _self_test():
    assert flatten([1, [2, [3]]]) == [1, 2, 3], 'flatten([1, [2, [3]]]) == [1, 2, 3]'
    assert flatten([]) == [], 'flatten([]) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
