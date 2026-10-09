"""al_31: simple utility module (stdlib only)."""

def strip_spaces(s):
    return s.strip()

def _run_tests():
    assert strip_spaces('  a  ') == 'a', 'al_31'
    assert strip_spaces('b') == 'b', 'al_31'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_31: all tests passed")
