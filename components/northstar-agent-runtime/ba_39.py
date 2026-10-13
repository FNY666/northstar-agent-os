"""ba_39: words utility."""

def words(s):
    return len(s.split())

def _tests():
    assert words('a b c') == 3
    assert words('x') == 1

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert words('a b c') == 3
    assert words('x') == 1

if __name__ == "__main__":
    _tests(); print('ok')
