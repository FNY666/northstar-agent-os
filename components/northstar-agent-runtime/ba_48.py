"""ba_48: bracket utility."""

def bracket(s):
    return '[%s]' % s

def _tests():
    assert bracket('a') == '[a]'
    assert bracket('') == '[]'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert bracket('a') == '[a]'
    assert bracket('') == '[]'

if __name__ == "__main__":
    _tests(); print('ok')
