"""an_07: absolute value. Stdlib only."""

def absv(x):
    return x if x >= 0 else -x

if __name__ == "__main__":
    assert absv(-7) == 7
    assert absv(7) == 7
    print("ok")
