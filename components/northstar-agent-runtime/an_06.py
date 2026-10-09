"""an_06: cube a number. Stdlib only."""

def cube(x):
    return x ** 3

if __name__ == "__main__":
    assert cube(2) == 8
    assert cube(-2) == -8
    print("ok")
