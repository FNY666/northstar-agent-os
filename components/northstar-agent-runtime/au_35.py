"""au_35: Linear interpolation."""
def lerp(a, b, t):
    """Interpolate between a and b at t in [0,1]."""
    return a + (b - a) * t

def _run_tests():
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(2, 4, 0) == 2

if __name__ == "__main__":
    _run_tests()
    print("au_35 OK")
