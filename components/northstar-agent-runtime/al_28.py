"""al_28: simple utility module (stdlib only)."""

def count_occurrences(items, x):
    return items.count(x)

def _run_tests():
    assert count_occurrences([1, 2, 1], 1) == 2, 'al_28'
    assert count_occurrences([1], 5) == 0, 'al_28'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_28: all tests passed")
