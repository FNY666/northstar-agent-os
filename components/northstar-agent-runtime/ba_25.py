"""ba_25: digits utility."""

def digits(x):
    return len(str(abs(int(x))))

def _tests():
    assert digits(123) == 3
    assert digits(7) == 1

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert digits(123) == 3
    assert digits(7) == 1

if __name__ == "__main__":
    _tests(); print('ok')
