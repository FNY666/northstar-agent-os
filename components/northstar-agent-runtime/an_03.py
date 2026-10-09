"""an_03: double a number. Stdlib only."""

def dbl(x):
    return x * 2

if __name__ == "__main__":
    assert dbl(4) == 8
    assert dbl(0) == 0
    print("ok")
