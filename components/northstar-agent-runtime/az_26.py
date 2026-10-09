"""Pad string on the left. stdlib only."""

def pad_left(s, n, ch=' '):
    return s.rjust(n, ch)

def test():
    assert pad_left('5', 3) == '  5'
    assert pad_left('5', 3, '0') == '005'
    assert pad_left('abcd', 2) == 'abcd'

if __name__ == '__main__':
    test(); print('ok')
