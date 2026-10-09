"""Truncate string with ellipsis. stdlib only."""

def truncate(s, n):
    return s if len(s) <= n else s[:n-3] + '...'

def test():
    assert truncate('abcdef', 5) == 'ab...'
    assert truncate('abc', 5) == 'abc'
    assert truncate('', 5) == ''

if __name__ == '__main__':
    test(); print('ok')
