"""an_16: maximum of a list. Stdlib only."""

def maxv(xs):
    m = xs[0]
    for x in xs[1:]:
        if x > m:
            m = x
    return m

if __name__ == "__main__":
    assert maxv([3, 1, 2]) == 3
    assert maxv([5]) == 5
    print("ok")
