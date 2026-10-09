"""al_33: simple utility module (stdlib only)."""

def ends_with_z(s):
    return s.endswith('z')

def _run_tests():
    assert ends_with_z('fizz') == True, 'al_33'
    assert ends_with_z('buzz') == True, 'al_33'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_33: all tests passed")
