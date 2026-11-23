"""ba_03: cube utility."""

def cube(x):
    return x ** 3

def _tests():
    assert cube(2) == 8
    assert cube(-1) == -1

if __name__ == "__main__":
    _tests(); print('ok')

def _tests():
    assert cube(2) == 8
    assert cube(-1) == -1

if __name__ == "__main__":
    _tests(); print('ok')
