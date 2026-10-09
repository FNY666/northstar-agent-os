"""an_12: sum of a list. Stdlib only."""

def total(xs):
    s = 0
    for x in xs:
        s += x
    return s

if __name__ == "__main__":
    assert total([1, 2, 3]) == 6
    assert total([]) == 0
    print("ok")
