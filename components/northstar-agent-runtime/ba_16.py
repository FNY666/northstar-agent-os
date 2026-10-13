"""ba_16: clamp01 utility."""

def clamp01(x):
    return max(0, min(1, x))

def _tests():
    assert clamp01(2) == 1
    assert clamp01(-1) == 0
    assert clamp01(0.5) == 0.5

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert clamp01(2) == 1
    assert clamp01(-1) == 0
    assert clamp01(0.5) == 0.5

if __name__ == "__main__":
    _tests(); print('ok')
