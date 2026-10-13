"""ba_18: per_mille utility."""

def per_mille(x):
    return x / 1000

def _tests():
    assert per_mille(1000) == 1.0
    assert per_mille(500) == 0.5

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert per_mille(1000) == 1.0
    assert per_mille(500) == 0.5

if __name__ == "__main__":
    _tests(); print('ok')
