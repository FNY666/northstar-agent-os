"""ba_24: first_digit utility."""

def first_digit(x):
    return int(str(abs(x))[0])

def _tests():
    assert first_digit(123) == 1
    assert first_digit(987) == 9

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert first_digit(123) == 1
    assert first_digit(987) == 9

if __name__ == "__main__":
    _tests(); print('ok')
