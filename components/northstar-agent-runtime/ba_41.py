"""ba_41: camel utility."""

def camel(s):
    return ''.join(w.capitalize() if i else w for i, w in enumerate(s.split('_')))

def _tests():
    assert camel('a_b') == 'aB'
    assert camel('x_y_z') == 'xYZ'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert camel('a_b') == 'aB'
    assert camel('x_y_z') == 'xYZ'

if __name__ == "__main__":
    _tests(); print('ok')
