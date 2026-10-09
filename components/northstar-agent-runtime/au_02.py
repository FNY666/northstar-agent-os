"""au_02: Check palindrome ignoring case/spaces."""
def is_palindrome(s):
    """True if s reads the same backwards (case-insensitive, spaces ignored)."""
    t = ''.join(s.lower().split())
    return t == t[::-1]

def _run_tests():
    assert is_palindrome('A man a plan a canal Panama')
    assert not is_palindrome('hello')

if __name__ == "__main__":
    _run_tests()
    print("au_02 OK")
