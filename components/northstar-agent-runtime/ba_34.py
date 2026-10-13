"""ba_34: reverse_str utility."""

def reverse_str(s):
    return s[::-1]

def _tests():
    assert reverse_str('abc') == 'cba'
    assert reverse_str('x') == 'x'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert reverse_str('abc') == 'cba'
    assert reverse_str('x') == 'x'

if __name__ == "__main__":
    _tests(); print('ok')
