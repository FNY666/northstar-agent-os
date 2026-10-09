"""am_31: count_char utility (stdlib only)."""

def count_char(s, ch):
    return s.count(ch)

def _run_tests():
    assert count_char('banana', 'a') == 3, 'am_31'
    assert count_char('x', 'q') == 0, 'am_31'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_31: all tests passed")
