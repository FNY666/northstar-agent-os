"""ba_36: char0 utility."""

def char0(s):
    return s[0]

def _tests():
    assert char0('abc') == 'a'
    assert char0('z') == 'z'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert char0('abc') == 'a'
    assert char0('z') == 'z'

if __name__ == "__main__":
    _tests(); print('ok')
