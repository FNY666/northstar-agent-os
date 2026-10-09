"""ba_45: question utility."""

def question(s):
    return s + '?'

def _tests():
    assert question('hi') == 'hi?'
    assert question('') == '?'

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert question('hi') == 'hi?'
    assert question('') == '?'

if __name__ == "__main__":
    _tests(); print('ok')
