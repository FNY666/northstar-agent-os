"""Median of list. stdlib only."""

def median(xs):
    s = sorted(xs)
    n = len(s)
    m = n // 2
    return (s[m-1] + s[m]) / 2 if n % 2 == 0 else s[m]

def test():
    assert median([1,3,2]) == 2
    assert median([1,2,3,4]) == 2.5
    assert median([5]) == 5

if __name__ == '__main__':
    test(); print('ok')
