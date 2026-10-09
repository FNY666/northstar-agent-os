"""ao_45: group_by utility (stdlib only)."""

def group_by(xs, key):
    from collections import defaultdict
    g = defaultdict(list)
    for x in xs: g[key(x)].append(x)
    return dict(g)


def _self_test():
    assert group_by([1,2,3,4], lambda x: x % 2) == {1:[1,3],0:[2,4]}, 'group_by([1,2,3,4], lambda x: x % 2) == {1:[1,3],0:[2,4]}'
    assert group_by([], str) == {}, 'group_by([], str) == {}'


if __name__ == "__main__":
    _self_test()
    print("ok")
