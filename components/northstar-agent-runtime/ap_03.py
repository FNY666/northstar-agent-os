"""flatten utility."""

def flatten(nested):
    out = []
    for x in nested:
        out += flatten(x) if isinstance(x, list) else [x]
    return out


def _self_test():
    assert flatten([1, [2, [3]], 4]) == [1, 2, 3, 4]
    assert flatten([]) == []


if __name__ == "__main__":
    _self_test()
    print("ap_03: OK")
