"""al_25: simple utility module (stdlib only)."""

def list_length(items):
    return len(items)

def _run_tests():
    assert list_length([1, 2]) == 2, 'al_25'
    assert list_length([]) == 0, 'al_25'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_25: all tests passed")
