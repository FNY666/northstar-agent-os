"""Clamp n to [lo, hi]. stdlib only."""

def clamp(n, lo, hi):
    return max(lo, min(hi, n))

def test():
    assert clamp(5, 0, 10) == 5
    assert clamp(-1, 0, 10) == 0
    assert clamp(99, 0, 10) == 10

if __name__ == '__main__':
    test(); print('ok')
