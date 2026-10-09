"""Palindrome check. stdlib only."""

def is_palindrome(s):
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]

def test():
    assert is_palindrome('Aba')
    assert is_palindrome('racecar')
    assert not is_palindrome('hello')

if __name__ == '__main__':
    test(); print('ok')
