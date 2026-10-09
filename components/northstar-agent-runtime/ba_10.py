"""ba_10: is_even utility."""

def is_even(x):
    return x % 2 == 0

def _tests():
    assert is_even(2) == True
    assert is_even(3) == False

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert is_even(2) == True
    assert is_even(3) == False

if __name__ == "__main__":
    _tests(); print('ok')
