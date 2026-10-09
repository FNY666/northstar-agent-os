"""al_17: simple utility module (stdlib only)."""

def min_of_two(a, b):
    return a if a < b else b

def _run_tests():
    assert min_of_two(3, 5) == 3, 'al_17'
    assert min_of_two(7, 2) == 2, 'al_17'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_17: all tests passed")
