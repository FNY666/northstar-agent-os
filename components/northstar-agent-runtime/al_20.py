"""al_20: simple utility module (stdlib only)."""

def string_length(s):
    return len(s)

def _run_tests():
    assert string_length('hello') == 5, 'al_20'
    assert string_length('') == 0, 'al_20'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_20: all tests passed")
