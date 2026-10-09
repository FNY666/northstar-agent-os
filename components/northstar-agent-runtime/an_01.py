"""an_01: increment a number by one. Stdlib only."""

def inc(x):
    return x + 1

if __name__ == "__main__":
    assert inc(0) == 1
    assert inc(-5) == -4
    print("ok")
