"""an_34: reverse a list. Stdlib only."""

def revl(xs):
    return list(reversed(xs))

if __name__ == "__main__":
    assert revl([1, 2, 3]) == [3, 2, 1]
    assert revl([]) == []
    print("ok")
