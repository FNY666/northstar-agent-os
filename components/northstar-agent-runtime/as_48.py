"""repeat_str utility."""

def repeat_str(s, n, sep=''):
    return sep.join([s] * n)


def _selftest():
    assert repeat_str("ab", 3) == "ababab"
    assert repeat_str("a", 2, "-") == "a-a"


if __name__ == "__main__":
    _selftest()
    print("ok")
