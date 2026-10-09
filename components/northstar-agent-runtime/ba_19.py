"""ba_19: ceil2 utility."""

def ceil2(x):
    return -((-x) // 2)

def _tests():
    assert ceil2(5) == 3
    assert ceil2(4) == 2

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert ceil2(5) == 3
    assert ceil2(4) == 2

if __name__ == "__main__":
    _tests(); print('ok')
