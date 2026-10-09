"""is_palindrome utility."""

def is_palindrome(s):
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]


def _self_test():
    assert is_palindrome('A man, a plan, a canal: Panama')
    assert not is_palindrome('hello')


if __name__ == "__main__":
    _self_test()
    print("ap_11: OK")
