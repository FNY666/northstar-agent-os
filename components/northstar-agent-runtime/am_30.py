"""am_30: split_words utility (stdlib only)."""

def split_words(s):
    return s.split()

def _run_tests():
    assert split_words('a b c') == ['a', 'b', 'c'], 'am_30'
    assert split_words('') == [], 'am_30'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_30: all tests passed")
