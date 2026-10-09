"""an_05: square a number. Stdlib only."""

def sq(x):
    return x * x

if __name__ == "__main__":
    assert sq(5) == 25
    assert sq(-3) == 9
    print("ok")
