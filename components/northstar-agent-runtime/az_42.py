"""Pairwise differences. stdlib only."""

def differences(xs):
    return [b - a for a, b in zip(xs, xs[1:])]

def test():
    assert differences([1,3,6]) == [2,3]
    assert differences([5]) == []
    assert differences([]) == []

if __name__ == '__main__':
    test(); print('ok')
