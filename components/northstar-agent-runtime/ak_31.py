"""ak_31: Group by key function."""

def group_by(xs, key):
    from collections import defaultdict
    d = defaultdict(list)
    for x in xs: d[key(x)].append(x)
    return dict(d)

if __name__ == '__main__':
    assert group_by([1, 2, 3, 4], lambda x: x % 2) == {1: [1, 3], 0: [2, 4]}
    assert group_by([], str) == {}
    print('ok')
