"""pad utility."""

def pad(s, n, c=' '):
    return s + c * max(0, n - len(s))


def _selftest():
    assert pad("hi", 5) == "hi   "
    assert pad("hello", 3) == "hello"


if __name__ == "__main__":
    _selftest()
    print("ok")
