"""Flatten one level. stdlib only."""

def flatten1(xs):
    out = []
    for x in xs:
        out.extend(x)
    return out

def test():
    assert flatten1([[1,2],[3]]) == [1,2,3]
    assert flatten1([]) == []
    assert flatten1([[]]) == []

if __name__ == '__main__':
    test(); print('ok')
