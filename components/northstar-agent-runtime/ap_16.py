"""group_by utility."""

def group_by(items, key):
    out = {}
    for x in items:
        out.setdefault(key(x), []).append(x)
    return out


def _self_test():
    assert group_by([1,2,3,4], lambda x: x%2) == {1:[1,3], 0:[2,4]}
    assert group_by([], len) == {}


if __name__ == "__main__":
    _self_test()
    print("ap_16: OK")
