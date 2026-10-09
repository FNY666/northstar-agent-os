"""am_32: is_palindrome utility (stdlib only)."""

def is_palindrome(s):
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]

def _run_tests():
    assert is_palindrome('Racecar') is True, 'am_32'
    assert is_palindrome('hello') is False, 'am_32'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_32: all tests passed")
