"""ba_46: quote utility."""

def quote(s):
    return '"%s"' % s

def _tests():
    assert quote('a') == '"a"'
    assert quote('') == '""'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert quote('a') == '"a"'
    assert quote('') == '""'

if __name__ == "__main__":
    _tests(); print('ok')
