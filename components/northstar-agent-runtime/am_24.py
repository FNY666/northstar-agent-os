"""am_24: strip_str utility (stdlib only)."""

def strip_str(s):
    return s.strip()

def _run_tests():
    assert strip_str('  hi  ') == 'hi', 'am_24'
    assert strip_str('x') == 'x', 'am_24'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_24: all tests passed")
