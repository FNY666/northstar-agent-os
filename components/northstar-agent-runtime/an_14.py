"""an_14: average of a list. Stdlib only."""

def avg(xs):
    return sum(xs) / len(xs)

if __name__ == "__main__":
    assert avg([2, 4]) == 3.0
    assert avg([5]) == 5.0
    print("ok")
