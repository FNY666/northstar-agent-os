"""al_24: simple utility module (stdlib only)."""

def list_sum(items):
    return sum(items)

def _run_tests():
    assert list_sum([1, 2, 3]) == 6, 'al_24'
    assert list_sum([]) == 0, 'al_24'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_24: all tests passed")
