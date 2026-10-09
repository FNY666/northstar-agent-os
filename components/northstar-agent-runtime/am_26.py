"""am_26: str_len utility (stdlib only)."""

def str_len(s):
    return len(s)

def _run_tests():
    assert str_len('hello') == 5, 'am_26'
    assert str_len('') == 0, 'am_26'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_26: all tests passed")
