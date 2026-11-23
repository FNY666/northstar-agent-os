"""ba_47: paren utility."""

def paren(s):
    return '(%s)' % s

def _tests():
    assert paren('a') == '(a)'
    assert paren('') == '()'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert paren('a') == '(a)'
    assert paren('') == '()'

if __name__ == "__main__":
    _tests(); print('ok')
