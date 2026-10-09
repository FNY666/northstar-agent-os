"""Normalize vector. stdlib only."""

def normalize(v):
    n = sum(x*x for x in v) ** 0.5
    return [x/n for x in v] if n else list(v)

def test():
    r = normalize([3.0,4.0])
    assert abs(r[0]-0.6) < 1e-9 and abs(r[1]-0.8) < 1e-9
    assert normalize([]) == []
    assert normalize([0.0]) == [0.0]

if __name__ == '__main__':
    test(); print('ok')
