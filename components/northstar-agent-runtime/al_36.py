"""al_36: simple utility module (stdlib only)."""

def floor_div(a, b):
    return a // b

def _run_tests():
    assert floor_div(7, 2) == 3, 'al_36'
    assert floor_div(-7, 2) == -4, 'al_36'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_36: all tests passed")
