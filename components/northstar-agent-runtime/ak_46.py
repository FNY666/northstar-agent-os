"""ak_46: Invert a dict (values->keys)."""

def invert(d):
    out = {}
    for k, v in d.items(): out.setdefault(v, []).append(k)
    return out

if __name__ == '__main__':
    assert invert({'a': 1, 'b': 1, 'c': 2}) == {1: ['a', 'b'], 2: ['c']}
    assert invert({}) == {}
    print('ok')
