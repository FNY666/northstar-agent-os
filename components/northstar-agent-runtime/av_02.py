"""Linear interpolation between a and b."""
def lerp(a, b, t):
    return a + (b - a) * t
if __name__ == "__main__":
    assert lerp(0, 10, 0.0) == 0
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(0, 10, 1.0) == 10
    print("ok")
