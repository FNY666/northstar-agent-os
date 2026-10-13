"""ba_11: is_odd utility."""

def is_odd(x):
    return x % 2 != 0

def _tests():
    assert is_odd(3) == True
    assert is_odd(2) == False

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert is_odd(3) == True
    assert is_odd(2) == False

if __name__ == "__main__":
    _tests(); print('ok')
