"""ax_30: pad_right utility (stdlib only)."""
def pad_right(s, n, ch=' '):
    return s.ljust(n, ch)


def run_tests():
    assert (pad_right('5', 3, '0')) == '500', "pad_right('5', 3, '0')"
    assert (pad_right('abc', 2)) == 'abc', "pad_right('abc', 2)"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_30: ok")
