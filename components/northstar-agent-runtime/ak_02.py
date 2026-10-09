"""ak_02: Check if a string is a palindrome."""

def is_palindrome(s):
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]

if __name__ == '__main__':
    assert is_palindrome('Racecar')
    assert is_palindrome('A man, a plan, a canal: Panama')
    assert not is_palindrome('hello')
    print('ok')
