"""ba_43: repeat utility."""

def repeat(s):
    return s * 2

def _tests():
    assert repeat('ab') == 'abab'
    assert repeat('x') == 'xx'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert repeat('ab') == 'abab'
    assert repeat('x') == 'xx'

if __name__ == "__main__":
    _tests(); print('ok')
