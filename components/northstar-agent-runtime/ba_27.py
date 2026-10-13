"""ba_27: reverse_int utility."""

def reverse_int(x):
    return int(str(abs(x))[::-1]) * (1 if x >= 0 else -1)

def _tests():
    assert reverse_int(123) == 321
    assert reverse_int(-45) == -54

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert reverse_int(123) == 321
    assert reverse_int(-45) == -54

if __name__ == "__main__":
    _tests(); print('ok')
