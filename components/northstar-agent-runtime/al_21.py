"""al_21: simple utility module (stdlib only)."""

def is_empty(x):
    return len(x) == 0

def _run_tests():
    assert is_empty([]) == True, 'al_21'
    assert is_empty([1]) == False, 'al_21'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_21: all tests passed")
