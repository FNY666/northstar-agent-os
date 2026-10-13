"""ba_40: slug utility."""

def slug(s):
    return '-'.join(s.lower().split())

def _tests():
    assert slug('A B') == 'a-b'
    assert slug('X Y Z') == 'x-y-z'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert slug('A B') == 'a-b'
    assert slug('X Y Z') == 'x-y-z'

if __name__ == "__main__":
    _tests(); print('ok')
