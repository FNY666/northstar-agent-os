"""al_19: simple utility module (stdlib only)."""

def reverse_string(s):
    return s[::-1]

def _run_tests():
    assert reverse_string('abc') == 'cba', 'al_19'
    assert reverse_string('') == '', 'al_19'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_19: all tests passed")
