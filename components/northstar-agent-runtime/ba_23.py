"""ba_23: last_digit utility."""

def last_digit(x):
    return abs(x) % 10

def _tests():
    assert last_digit(123) == 3
    assert last_digit(-47) == 7

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert last_digit(123) == 3
    assert last_digit(-47) == 7

if __name__ == "__main__":
    _tests(); print('ok')
