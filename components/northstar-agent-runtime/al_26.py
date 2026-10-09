"""al_26: simple utility module (stdlib only)."""

def head_two(items):
    return items[:2]

def _run_tests():
    assert head_two([1, 2, 3]) == [1, 2], 'al_26'
    assert head_two([1]) == [1], 'al_26'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_26: all tests passed")
