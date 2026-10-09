"""al_27: simple utility module (stdlib only)."""

def tail_two(items):
    return items[-2:]

def _run_tests():
    assert tail_two([1, 2, 3]) == [2, 3], 'al_27'
    assert tail_two([1]) == [1], 'al_27'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_27: all tests passed")
