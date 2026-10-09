"""truncate utility."""

def truncate(s, n, suffix='...'):
    return s if len(s) <= n else s[:n-len(suffix)]+suffix


def _self_test():
    assert truncate('hello world', 5) == 'he...'
    assert truncate('hi', 5) == 'hi'


if __name__ == "__main__":
    _self_test()
    print("ap_39: OK")
