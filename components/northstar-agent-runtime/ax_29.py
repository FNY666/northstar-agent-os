"""ax_29: pad_left utility (stdlib only)."""
def pad_left(s, n, ch=' '):
    return s.rjust(n, ch)


def run_tests():
    assert (pad_left('5', 3, '0')) == '005', "pad_left('5', 3, '0')"
    assert (pad_left('abc', 2)) == 'abc', "pad_left('abc', 2)"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_29: ok")
