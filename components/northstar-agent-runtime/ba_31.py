"""ba_31: strip utility."""

def strip(s):
    return s.strip()

def _tests():
    assert strip('  a ') == 'a'
    assert strip(' b') == 'b'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert strip('  a ') == 'a'
    assert strip(' b') == 'b'

if __name__ == "__main__":
    _tests(); print('ok')
