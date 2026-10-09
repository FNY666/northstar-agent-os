"""ax_04: is_palindrome utility (stdlib only)."""
def is_palindrome(s):
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]


def run_tests():
    assert (is_palindrome('Racecar')) == True, "is_palindrome('Racecar')"
    assert (is_palindrome('hello')) == False, "is_palindrome('hello')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_04: ok")
