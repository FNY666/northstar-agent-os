"""Frequency counter. stdlib only."""

def counter(xs):
    d = {}
    for x in xs:
        d[x] = d.get(x, 0) + 1
    return d

def test():
    assert counter([1,2,2]) == {1:1, 2:2}
    assert counter([]) == {}
    assert counter('aab') == {'a':2, 'b':1}

if __name__ == '__main__':
    test(); print('ok')
