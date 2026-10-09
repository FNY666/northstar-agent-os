"""al_34: simple utility module (stdlib only)."""

def contains_sub(s, sub):
    return sub in s

def _run_tests():
    assert contains_sub('hello', 'ell') == True, 'al_34'
    assert contains_sub('hello', 'xyz') == False, 'al_34'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_34: all tests passed")
