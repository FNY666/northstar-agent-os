"""an_04: halve a number. Stdlib only."""

def half(x):
    return x / 2

if __name__ == "__main__":
    assert half(8) == 4
    assert half(1) == 0.5
    print("ok")
