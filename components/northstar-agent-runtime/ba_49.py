"""ba_49: truncate utility."""

def truncate(s):
    return s[:10]

def _tests():
    assert truncate('abcdefghijklmnop') == 'abcdefghij'
    assert truncate('ab') == 'ab'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert truncate('abcdefghijklmnop') == 'abcdefghij'
    assert truncate('ab') == 'ab'

if __name__ == "__main__":
    _tests(); print('ok')
