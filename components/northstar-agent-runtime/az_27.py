"""Pad string on the right. stdlib only."""

def pad_right(s, n, ch=' '):
    return s.ljust(n, ch)

def test():
    assert pad_right('5', 3) == '5  '
    assert pad_right('5', 3, '0') == '500'
    assert pad_right('abcd', 2) == 'abcd'

if __name__ == '__main__':
    test(); print('ok')
