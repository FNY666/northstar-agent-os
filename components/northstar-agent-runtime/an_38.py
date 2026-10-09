"""an_38: sum of squares. Stdlib only."""

def sumsq(xs):
    return sum(x * x for x in xs)

if __name__ == "__main__":
    assert sumsq([1, 2, 3]) == 14
    assert sumsq([]) == 0
    print("ok")
