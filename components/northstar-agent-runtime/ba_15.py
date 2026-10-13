"""ba_15: sign utility."""

def sign(x):
    return (x > 0) - (x < 0)

def _tests():
    assert sign(5) == 1
    assert sign(-5) == -1
    assert sign(0) == 0

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert sign(5) == 1
    assert sign(-5) == -1
    assert sign(0) == 0

if __name__ == "__main__":
    _tests(); print('ok')
