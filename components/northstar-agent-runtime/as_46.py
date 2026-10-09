"""truncate utility."""

def truncate(s, n, e='...'):
    return s if len(s) <= n else s[:n - len(e)] + e


def _selftest():
    assert truncate("hello", 4) == "h..."
    assert truncate("hi", 10) == "hi"


if __name__ == "__main__":
    _selftest()
    print("ok")
