"""al_44: simple utility module (stdlib only)."""

def swap(a, b):
    return (b, a)

def _run_tests():
    assert swap(1, 2) == (2, 1), 'al_44'
    assert swap('a', 'b') == ('b', 'a'), 'al_44'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_44: all tests passed")
