"""ba_38: no_space utility."""

def no_space(s):
    return s.replace(' ', '')

def _tests():
    assert no_space('a b') == 'ab'
    assert no_space('x y z') == 'xyz'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert no_space('a b') == 'ab'
    assert no_space('x y z') == 'xyz'

if __name__ == "__main__":
    _tests(); print('ok')
