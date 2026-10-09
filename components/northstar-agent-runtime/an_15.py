"""an_15: minimum of a list. Stdlib only."""

def minv(xs):
    m = xs[0]
    for x in xs[1:]:
        if x < m:
            m = x
    return m

if __name__ == "__main__":
    assert minv([3, 1, 2]) == 1
    assert minv([5]) == 5
    print("ok")
