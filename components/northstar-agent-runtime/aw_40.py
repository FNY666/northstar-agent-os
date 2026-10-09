"""Adjacent pairs."""
def pairwise(xs):
    return list(zip(xs, xs[1:]))
if __name__ == "__main__":
    assert pairwise([1,2,3]) == [(1,2),(2,3)]
    assert pairwise([1]) == []
    assert pairwise([]) == []
    print("ok")
