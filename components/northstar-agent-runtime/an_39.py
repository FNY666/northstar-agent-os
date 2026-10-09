"""an_39: factorial. Stdlib only."""

def fact(n):
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r

if __name__ == "__main__":
    assert fact(5) == 120
    assert fact(0) == 1
    print("ok")
