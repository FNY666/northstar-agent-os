"""ax_28: truncate utility (stdlib only)."""
def truncate(s, n):
    return s if len(s) <= n else (s[:n-3] + '...' if n > 3 else s[:n])


def run_tests():
    assert (truncate('hello world', 8)) == 'hello...', "truncate('hello world', 8)"
    assert (truncate('hi', 8)) == 'hi', "truncate('hi', 8)"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_28: ok")
