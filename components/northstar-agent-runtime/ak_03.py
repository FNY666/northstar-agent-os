"""ak_03: Flatten a nested list."""

def flatten(xs):
    out = []
    for x in xs:
        if isinstance(x, list):
            out.extend(flatten(x))
        else:
            out.append(x)
    return out

if __name__ == '__main__':
    assert flatten([1, [2, [3]], 4]) == [1, 2, 3, 4]
    assert flatten([]) == []
    print('ok')
