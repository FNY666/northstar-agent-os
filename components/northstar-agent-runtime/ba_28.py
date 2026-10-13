"""ba_28: is_pal utility."""

def is_pal(s):
    return str(s) == str(s)[::-1]

def _tests():
    assert is_pal(121) == True
    assert is_pal(123) == False

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert is_pal(121) == True
    assert is_pal(123) == False

if __name__ == "__main__":
    _tests(); print('ok')
