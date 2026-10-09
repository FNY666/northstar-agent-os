"""ba_26: digit_sum utility."""

def digit_sum(x):
    return sum(int(c) for c in str(abs(int(x))))

def _tests():
    assert digit_sum(123) == 6
    assert digit_sum(99) == 18

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert digit_sum(123) == 6
    assert digit_sum(99) == 18

if __name__ == "__main__":
    _tests(); print('ok')
