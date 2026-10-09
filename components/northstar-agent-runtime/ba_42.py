"""ba_42: snake utility."""

def snake(s):
    return '_'.join(w.lower() for w in s.split())

def _tests():
    assert snake('A B') == 'a_b'
    assert snake('X Y') == 'x_y'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert snake('A B') == 'a_b'
    assert snake('X Y') == 'x_y'

if __name__ == "__main__":
    _tests(); print('ok')
