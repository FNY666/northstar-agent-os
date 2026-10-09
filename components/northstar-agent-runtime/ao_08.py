"""ao_08: is_palindrome utility (stdlib only)."""

def is_palindrome(s):
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]


def _self_test():
    assert is_palindrome('Aba'), "is_palindrome('Aba')"
    assert not is_palindrome('abc'), "not is_palindrome('abc')"


if __name__ == "__main__":
    _self_test()
    print("ok")
