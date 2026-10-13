"""ba_33: swapcase utility."""

def swapcase(s):
    return s.swapcase()

def _tests():
    assert swapcase('aB') == 'Ab'
    assert swapcase('Xy') == 'xY'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert swapcase('aB') == 'Ab'
    assert swapcase('Xy') == 'xY'

if __name__ == "__main__":
    _tests(); print('ok')
