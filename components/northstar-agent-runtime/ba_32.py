"""ba_32: title utility."""

def title(s):
    return s.title()

def _tests():
    assert title('a b') == 'A B'
    assert title('x') == 'X'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert title('a b') == 'A B'
    assert title('x') == 'X'

if __name__ == "__main__":
    _tests(); print('ok')
