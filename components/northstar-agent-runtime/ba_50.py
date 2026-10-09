"""ba_50: pad2 utility."""

def pad2(s):
    return s.zfill(2)

def _tests():
    assert pad2('5') == '05'
    assert pad2('12') == '12'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert pad2('5') == '05'
    assert pad2('12') == '12'

if __name__ == "__main__":
    _tests(); print('ok')
