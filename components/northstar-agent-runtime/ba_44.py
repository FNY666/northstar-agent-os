"""ba_44: exclaim utility."""

def exclaim(s):
    return s + '!'

def _tests():
    assert exclaim('hi') == 'hi!'
    assert exclaim('') == '!'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert exclaim('hi') == 'hi!'
    assert exclaim('') == '!'

if __name__ == "__main__":
    _tests(); print('ok')
