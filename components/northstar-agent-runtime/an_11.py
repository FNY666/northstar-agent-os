"""an_11: sign of a number. Stdlib only."""

def sign(x):
    return 1 if x > 0 else (-1 if x < 0 else 0)

if __name__ == "__main__":
    assert sign(10) == 1
    assert sign(-3) == -1
    assert sign(0) == 0
    print("ok")
