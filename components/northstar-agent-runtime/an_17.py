"""an_17: range (max-min) of a list. Stdlib only."""

def rng(xs):
    return max(xs) - min(xs)

if __name__ == "__main__":
    assert rng([1, 5, 3]) == 4
    assert rng([7]) == 0
    print("ok")
