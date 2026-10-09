"""an_13: product of a list. Stdlib only."""

def prod(xs):
    p = 1
    for x in xs:
        p *= x
    return p

if __name__ == "__main__":
    assert prod([2, 3, 4]) == 24
    assert prod([]) == 1
    print("ok")
