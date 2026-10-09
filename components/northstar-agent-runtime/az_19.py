"""Reverse a string. stdlib only."""

def reverse_str(s):
    return s[::-1]

def test():
    assert reverse_str('abc') == 'cba'
    assert reverse_str('') == ''
    assert reverse_str('a') == 'a'

if __name__ == '__main__':
    test(); print('ok')
