"""ba_37: char_last utility."""

def char_last(s):
    return s[-1]

def _tests():
    assert char_last('abc') == 'c'
    assert char_last('z') == 'z'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert char_last('abc') == 'c'
    assert char_last('z') == 'z'

if __name__ == "__main__":
    _tests(); print('ok')
