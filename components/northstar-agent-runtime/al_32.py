"""al_32: simple utility module (stdlib only)."""

def starts_with_a(s):
    return s.startswith('a')

def _run_tests():
    assert starts_with_a('apple') == True, 'al_32'
    assert starts_with_a('banana') == False, 'al_32'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_32: all tests passed")
